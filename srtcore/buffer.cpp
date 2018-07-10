/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

/*****************************************************************************
Copyright (c) 2001 - 2011, The Board of Trustees of the University of Illinois.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the
  above copyright notice, this list of conditions
  and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the University of Illinois
  nor the names of its contributors may be used to
  endorse or promote products derived from this
  software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

/*****************************************************************************
written by
   Yunhong Gu, last updated 03/12/2011
modified by
   Haivision Systems Inc.
*****************************************************************************/

#include <cstring>
#include <cmath>
#include "buffer.h"
#include "packet.h"
#include "core.h" // provides some constants
#include "logging.h"

using namespace std;

extern logging::Logger mglog, dlog, tslog;

CSndBuffer::CSndBuffer(int size, int mss):
m_BufLock(),
m_pBlock(NULL),
m_pFirstBlock(NULL),
m_pCurrBlock(NULL),
m_pLastBlock(NULL),
m_pBuffer(NULL),
m_iNextMsgNo(1),
m_iSize(size),
m_iMSS(mss),
m_iCount(0)
,m_iBytesCount(0)
,m_ullLastOriginTime_us(0)
#ifdef SRT_ENABLE_SNDBUFSZ_MAVG
,m_LastSamplingTime(0)
,m_iCountMAvg(0)
,m_iBytesCountMAvg(0)
,m_TimespanMAvg(0)
#endif
,m_iInRatePktsCount(0)
,m_iInRateBytesCount(0)
,m_InRateStartTime(0)
,m_InRatePeriod(CUDT::SND_INPUTRATE_FAST_START_US)   // 0.5 sec (fast start)
,m_iInRateBps(CUDT::SND_INPUTRATE_INITIAL_BPS)
,m_iAvgPayloadSz(SRT_LIVE_DEF_PLSIZE)
{
   // initial physical buffer of "size"
   m_pBuffer = new Buffer;
   m_pBuffer->m_pcData = new char [m_iSize * m_iMSS];
   m_pBuffer->m_iSize = m_iSize;
   m_pBuffer->m_pNext = NULL;

   // circular linked list for out bound packets
   m_pBlock = new Block;
   Block* pb = m_pBlock;
   for (int i = 1; i < m_iSize; ++ i)
   {
      pb->m_pNext = new Block;
      pb->m_iMsgNoBitset = 0;
      pb = pb->m_pNext;
   }
   pb->m_pNext = m_pBlock;

   pb = m_pBlock;
   char* pc = m_pBuffer->m_pcData;
   for (int i = 0; i < m_iSize; ++ i)
   {
      pb->m_pcData = pc;
      pb = pb->m_pNext;
      pc += m_iMSS;
   }

   m_pFirstBlock = m_pCurrBlock = m_pLastBlock = m_pBlock;

   pthread_mutex_init(&m_BufLock, NULL);
}

CSndBuffer::~CSndBuffer()
{
   Block* pb = m_pBlock->m_pNext;
   while (pb != m_pBlock)
   {
      Block* temp = pb;
      pb = pb->m_pNext;
      delete temp;
   }
   delete m_pBlock;

   while (m_pBuffer != NULL)
   {
      Buffer* temp = m_pBuffer;
      m_pBuffer = m_pBuffer->m_pNext;
      delete [] temp->m_pcData;
      delete temp;
   }

   pthread_mutex_destroy(&m_BufLock);
}

void CSndBuffer::addBuffer(const char* data, int len, int ttl, bool order, uint64_t srctime, ref_t<int32_t> r_seqno, ref_t<int32_t> r_msgno)
{
    int32_t& msgno = *r_msgno;
    int32_t& seqno = *r_seqno;

    int size = len / m_iMSS;
    if ((len % m_iMSS) != 0)
        size ++;

    HLOGC(mglog.Debug, log << "addBuffer: size=" << m_iCount << " reserved=" << m_iSize << " needs=" << size << " buffers for " << len << " bytes");

    // dynamically increase sender buffer
    while (size + m_iCount >= m_iSize)
    {
        HLOGC(mglog.Debug, log << "addBuffer: ... still lacking " << (size + m_iCount - m_iSize) << " buffers...");
        increase();
    }

    uint64_t time = CTimer::getTime();
    int32_t inorder = order ? MSGNO_PACKET_INORDER::mask : 0;

    HLOGC(dlog.Debug, log << CONID() << "addBuffer: adding "
        << size << " packets (" << len << " bytes) to send, msgno=" << m_iNextMsgNo
        << (inorder ? "" : " NOT") << " in order");

    // The sequence number passed to this function is the sequence number
    // that the very first packet from the packet series should get here.
    // If there's more than one packet, this function must increase it by itself
    // and then return the accordingly modified sequence number in the reference.

    Block* s = m_pLastBlock;
    msgno = m_iNextMsgNo;
    for (int i = 0; i < size; ++ i)
    {
        int pktlen = len - i * m_iMSS;
        if (pktlen > m_iMSS)
            pktlen = m_iMSS;

        HLOGC(dlog.Debug, log << "addBuffer: seq=" << seqno << " spreading from=" << (i*m_iMSS) << " size=" << pktlen << " TO BUFFER:" << (void*)s->m_pcData);
        memcpy(s->m_pcData, data + i * m_iMSS, pktlen);
        s->m_iLength = pktlen;

        s->m_iSeqNo = seqno;
        seqno = CSeqNo::incseq(seqno);

        s->m_iMsgNoBitset = m_iNextMsgNo | inorder;
        if (i == 0)
            s->m_iMsgNoBitset |= PacketBoundaryBits(PB_FIRST);
        if (i == size - 1)
            s->m_iMsgNoBitset |= PacketBoundaryBits(PB_LAST);
        // NOTE: if i is neither 0 nor size-1, it resuls with PB_SUBSEQUENT.
        //       if i == 0 == size-1, it results with PB_SOLO. 
        // Packets assigned to one message can be:
        // [PB_FIRST] [PB_SUBSEQUENT] [PB_SUBSEQUENT] [PB_LAST] - 4 packets per message
        // [PB_FIRST] [PB_LAST] - 2 packets per message
        // [PB_SOLO] - 1 packet per message

        s->m_ullSourceTime_us = srctime;
        s->m_ullOriginTime_us = time;
        s->m_iTTL = ttl;

        // XXX unchecked condition: s->m_pNext == NULL.
        // Should never happen, as the call to increase() should ensure enough buffers.
        s = s->m_pNext;
    }
    m_pLastBlock = s;

    CGuard::enterCS(m_BufLock);
    m_iCount += size;

    m_iBytesCount += len;
    m_ullLastOriginTime_us = time;

    updInputRate(time, size, len);

#ifdef SRT_ENABLE_SNDBUFSZ_MAVG
    updAvgBufSize(time);
#endif

    CGuard::leaveCS(m_BufLock);


    // MSGNO_SEQ::mask has a form: 00000011111111...
    // At least it's known that it's from some index inside til the end (to bit 0).
    // If this value has been reached in a step of incrementation, it means that the
    // maximum value has been reached. Casting to int32_t to ensure the same sign
    // in comparison, although it's far from reaching the sign bit.

    m_iNextMsgNo ++;
    if (m_iNextMsgNo == int32_t(MSGNO_SEQ::mask))
        m_iNextMsgNo = 1;
}

void CSndBuffer::setInputRateSmpPeriod(int period)
{
   m_InRatePeriod = (uint64_t)period; //(usec) 0=no input rate calculation
}

void CSndBuffer::updInputRate(uint64_t time, int pkts, int bytes)
{
   if (m_InRatePeriod == 0)
      ;//no input rate calculation
   else if (m_InRateStartTime == 0)
      m_InRateStartTime = time;
   else
   {
      m_iInRatePktsCount += pkts;
      m_iInRateBytesCount += bytes;
      if ((time - m_InRateStartTime) > m_InRatePeriod) {
         //Payload average size
         m_iAvgPayloadSz = m_iInRateBytesCount / m_iInRatePktsCount;
         //Required Byte/sec rate (payload + headers)
         m_iInRateBytesCount += (m_iInRatePktsCount * CPacket::SRT_DATA_HDR_SIZE);
         m_iInRateBps = (int)(((int64_t)m_iInRateBytesCount * 1000000) / (time - m_InRateStartTime));

         HLOGF(dlog.Debug, "updInputRate: pkts:%d bytes:%d avg=%d rate=%d kbps interval=%llu\n",
            m_iInRateBytesCount, m_iInRatePktsCount, m_iAvgPayloadSz, (m_iInRateBps*8)/1000,
            (unsigned long long)(time - m_InRateStartTime));

         m_iInRatePktsCount = 0;
         m_iInRateBytesCount = 0;
         m_InRateStartTime = time;
      }
   }
}

int CSndBuffer::getInputRate(ref_t<int> r_payloadsz, ref_t<uint64_t> r_period)
{
    int& payloadsz = *r_payloadsz;
    uint64_t& period = *r_period;
    uint64_t time = CTimer::getTime();

    if ((m_InRatePeriod != 0)
            &&  (m_InRateStartTime != 0) 
            &&  ((time - m_InRateStartTime) > m_InRatePeriod))
    {
        //Packet size with headers
        if (m_iInRatePktsCount == 0)
            m_iAvgPayloadSz = 0;
        else
            m_iAvgPayloadSz = m_iInRateBytesCount / m_iInRatePktsCount;

        //include packet headers: SRT + UDP + IP
        int64_t llBytesCount = (int64_t)m_iInRateBytesCount + (m_iInRatePktsCount * (CPacket::HDR_SIZE + CPacket::UDP_HDR_SIZE));
        //Byte/sec rate
        m_iInRateBps = (int)((llBytesCount * 1000000) / (time - m_InRateStartTime));
        m_iInRatePktsCount = 0;
        m_iInRateBytesCount = 0;
        m_InRateStartTime = time;
    }
    payloadsz = m_iAvgPayloadSz;
    period = m_InRatePeriod;
    return(m_iInRateBps);
}

int CSndBuffer::addBufferFromFile(fstream& ifs, int len)
{
   int size = len / m_iMSS;
   if ((len % m_iMSS) != 0)
      size ++;

   HLOGC(mglog.Debug, log << "addBufferFromFile: size=" << m_iCount << " reserved=" << m_iSize << " needs=" << size << " buffers for " << len << " bytes");

   // dynamically increase sender buffer
   while (size + m_iCount >= m_iSize)
   {
      HLOGC(mglog.Debug, log << "addBufferFromFile: ... still lacking " << (size + m_iCount - m_iSize) << " buffers...");
      increase();
   }

   HLOGC(dlog.Debug, log << CONID() << "addBufferFromFile: adding "
       << size << " packets (" << len << " bytes) to send, msgno=" << m_iNextMsgNo);

   Block* s = m_pLastBlock;
   int total = 0;
   for (int i = 0; i < size; ++ i)
   {
      if (ifs.bad() || ifs.fail() || ifs.eof())
         break;

      int pktlen = len - i * m_iMSS;
      if (pktlen > m_iMSS)
         pktlen = m_iMSS;

      HLOGC(dlog.Debug, log << "addBufferFromFile: reading from=" << (i*m_iMSS) << " size=" << pktlen << " TO BUFFER:" << (void*)s->m_pcData);
      ifs.read(s->m_pcData, pktlen);
      if ((pktlen = int(ifs.gcount())) <= 0)
         break;

      // currently file transfer is only available in streaming mode, message is always in order, ttl = infinite
      s->m_iMsgNoBitset = m_iNextMsgNo | MSGNO_PACKET_INORDER::mask;
      if (i == 0)
         s->m_iMsgNoBitset |= PacketBoundaryBits(PB_FIRST);
      if (i == size - 1)
         s->m_iMsgNoBitset |= PacketBoundaryBits(PB_LAST);
      // NOTE: PB_FIRST | PB_LAST == PB_SOLO.
      // none of PB_FIRST & PB_LAST == PB_SUBSEQUENT.

      s->m_iLength = pktlen;
      s->m_iTTL = -1;
      s = s->m_pNext;

      total += pktlen;
   }
   m_pLastBlock = s;

   CGuard::enterCS(m_BufLock);
   m_iCount += size;
   m_iBytesCount += total;

   CGuard::leaveCS(m_BufLock);

   m_iNextMsgNo ++;
   if (m_iNextMsgNo == int32_t(MSGNO_SEQ::mask))
      m_iNextMsgNo = 1;

   return total;
}

int CSndBuffer::extractDataToSend(ref_t<CPacket> r_packet, ref_t<uint64_t> srctime, int kflgs)
{
   // No data to read
   if (m_pCurrBlock == m_pLastBlock)
      return 0;

   // Make the packet REFLECT the data stored in the buffer.
   r_packet.get().m_pcData = m_pCurrBlock->m_pcData;
   int readlen = m_pCurrBlock->m_iLength;
   r_packet.get().setLength(readlen);
   r_packet.get().m_iSeqNo = m_pCurrBlock->m_iSeqNo;

   // XXX This is probably done because the encryption should happen
   // just once, and so this sets the encryption flags to both msgno bitset
   // IN THE PACKET and IN THE BLOCK. This is probably to make the encryption
   // happen at the time when scheduling a new packet to send, but the packet
   // must remain in the send buffer until it's ACKed. For the case of rexmit
   // the packet will be taken "as is" (that is, already encrypted).
   //
   // The problem is in the order of things:
   // 0. When the application stores the data, some of the flags for PH_MSGNO are set.
   // 1. The readData() is called to get the original data sent by the application.
   // 2. The data are original and must be encrypted. They WILL BE encrypted, later.
   // 3. So far we are in readData() so the encryption flags must be updated NOW because
   //    later we won't have access to the block's data.
   // 4. After exiting from readData(), the packet is being encrypted. It's immediately
   //    sent, however the data must remain in the sending buffer until they are ACKed.
   // 5. In case when rexmission is needed, the second overloaded version of readData
   //    is being called, and the buffer + PH_MSGNO value is extracted. All interesting
   //    flags must be present and correct at that time.
   //
   // The only sensible way to fix this problem is to encrypt the packet not after
   // extracting from here, but when the packet is stored into CSndBuffer. The appropriate
   // flags for PH_MSGNO will be applied directly there. Then here the value for setting
   // PH_MSGNO will be set as is.

   if (kflgs == -1)
   {
       HLOGC(dlog.Debug, log << CONID() << " CSndBuffer: ERROR: encryption required and not possible. NOT SENDING.");
       readlen = 0;
   }
   else
   {
       m_pCurrBlock->m_iMsgNoBitset |= MSGNO_ENCKEYSPEC::wrap(kflgs);
   }
   r_packet.get().m_iMsgNo = m_pCurrBlock->m_iMsgNoBitset;

   *srctime =
      m_pCurrBlock->m_ullSourceTime_us ? m_pCurrBlock->m_ullSourceTime_us :
      m_pCurrBlock->m_ullOriginTime_us;

   m_pCurrBlock = m_pCurrBlock->m_pNext;

   HLOGC(dlog.Debug, log << CONID() << "CSndBuffer: extracting packet size=" << readlen << " to send");

   return readlen;
}

int CSndBuffer::extractDataToSend(const int offset, ref_t<CPacket> r_packet, ref_t<uint64_t> r_srctime, ref_t<int> r_msglen)
{
   int32_t& msgno_bitset = r_packet.get().m_iMsgNo;
   uint64_t& srctime = *r_srctime;
   int& msglen = *r_msglen;

   CGuard bufferguard(m_BufLock);

   Block* p = m_pFirstBlock;

   // XXX Suboptimal procedure to keep the blocks identifiable
   // by sequence number. Consider using some circular buffer.
   for (int i = 0; i < offset; ++ i)
      p = p->m_pNext;

   // Check if the block that is the next candidate to send (m_pCurrBlock pointing) is stale.

   // If so, then inform the caller that it should first take care of the whole
   // message (all blocks with that message id). Shift the m_pCurrBlock pointer
   // to the position past the last of them. Then return -1 and set the
   // msgno_bitset return reference to the message id that should be dropped as
   // a whole.

   // After taking care of that, the caller should immediately call this function again,
   // this time possibly in order to find the real data to be sent.

   // if found block is stale
   // (This is for messages that have declared TTL - messages that fail to be sent
   // before the TTL defined time comes, will be dropped).
   if ((p->m_iTTL >= 0) && ((CTimer::getTime() - p->m_ullOriginTime_us) / 1000 > (uint64_t)p->m_iTTL))
   {
      int32_t msgno = p->getMsgSeq();
      msglen = 1;
      p = p->m_pNext;
      bool move = false;
      while (msgno == p->getMsgSeq())
      {
         if (p == m_pCurrBlock)
            move = true;
         p = p->m_pNext;
         if (move)
            m_pCurrBlock = p;
         msglen ++;
      }

      HLOGC(dlog.Debug, log << "CSndBuffer::readData: due to TTL exceeded, " << msglen << " messages to drop, up to " << msgno);

      // If readData returns -1, then msgno_bitset is understood as a Message ID to drop.
      // This means that in this case it should be written by the message sequence value only
      // (not the whole 4-byte bitset written at PH_MSGNO).
      msgno_bitset = msgno;
      return -1;
   }

   r_packet.get().m_pcData = p->m_pcData;
   int readlen = p->m_iLength;
   r_packet.get().setLength(readlen);

   // XXX Here the value predicted to be applied to PH_MSGNO field is extracted.
   // As this function is predicted to extract the data to send as a rexmited packet,
   // the packet must be in the form ready to send - so, in case of encryption,
   // encrypted, and with all ENC flags already set. So, the first call to send
   // the packet originally (the other overload of this function) must set these
   // flags.
   r_packet.get().m_iMsgNo = p->m_iMsgNoBitset;

   srctime = 
      p->m_ullSourceTime_us ? p->m_ullSourceTime_us :
      p->m_ullOriginTime_us;

   HLOGC(dlog.Debug, log << CONID() << "CSndBuffer: extracting packet size=" << readlen << " to send [REXMIT]");

   return readlen;
}

void CSndBuffer::ackData(int offset)
{
   CGuard bufferguard(m_BufLock);

   bool move = false;
   for (int i = 0; i < offset; ++ i)
   {
      m_iBytesCount -= m_pFirstBlock->m_iLength;
      if (m_pFirstBlock == m_pCurrBlock)
          move = true;
      m_pFirstBlock = m_pFirstBlock->m_pNext;
   }
   if (move)
       m_pCurrBlock = m_pFirstBlock;

   m_iCount -= offset;

#ifdef SRT_ENABLE_SNDBUFSZ_MAVG
   updAvgBufSize(CTimer::getTime());
#endif

   CTimer::triggerEvent();
}

int CSndBuffer::getCurrBufSize() const
{
   return m_iCount;
}

#ifdef SRT_ENABLE_SNDBUFSZ_MAVG

int CSndBuffer::getAvgBufSize(ref_t<int> r_bytes, ref_t<int> r_tsp)
{
    int& bytes = *r_bytes;
    int& timespan = *r_tsp;
    CGuard bufferguard(m_BufLock); /* Consistency of pkts vs. bytes vs. spantime */

    /* update stats in case there was no add/ack activity lately */
    updAvgBufSize(CTimer::getTime());

    bytes = m_iBytesCountMAvg;
    timespan = m_TimespanMAvg;
    return(m_iCountMAvg);
}

void CSndBuffer::updAvgBufSize(uint64_t now)
{
   uint64_t elapsed = (now - m_LastSamplingTime) / 1000; //ms since last sampling

   if ((1000000 / SRT_MAVG_SAMPLING_RATE) / 1000 > elapsed)
      return;

   if (1000000 < elapsed)
   {
      /* No sampling in last 1 sec, initialize average */
      m_iCountMAvg = getCurrBufSize(Ref(m_iBytesCountMAvg), Ref(m_TimespanMAvg));
      m_LastSamplingTime = now;
   } 
   else //((1000000 / SRT_MAVG_SAMPLING_RATE) / 1000 <= elapsed)
   {
      /*
      * weight last average value between -1 sec and last sampling time (LST)
      * and new value between last sampling time and now
      *                                      |elapsed|
      *   +----------------------------------+-------+
      *  -1                                 LST      0(now)
      */
      int instspan;
      int bytescount;
      int count = getCurrBufSize(Ref(bytescount), Ref(instspan));

      HLOGF(dlog.Debug, "updAvgBufSize: %6llu: %6d %6d %6d ms\n",
              (unsigned long long)elapsed, count, bytescount, instspan);

      m_iCountMAvg      = (int)(((count      * (1000 - elapsed)) + (count      * elapsed)) / 1000);
      m_iBytesCountMAvg = (int)(((bytescount * (1000 - elapsed)) + (bytescount * elapsed)) / 1000);
      m_TimespanMAvg    = (int)(((instspan   * (1000 - elapsed)) + (instspan   * elapsed)) / 1000);
      m_LastSamplingTime = now;
   }
}

#endif /* SRT_ENABLE_SNDBUFSZ_MAVG */

int CSndBuffer::getCurrBufSize(ref_t<int> bytes, ref_t<int> timespan)
{
   *bytes = m_iBytesCount;
   /* 
   * Timespan can be less then 1000 us (1 ms) if few packets. 
   * Also, if there is only one pkt in buffer, the time difference will be 0.
   * Therefore, always add 1 ms if not empty.
   */
   *timespan = 0 < m_iCount ? int((m_ullLastOriginTime_us - m_pFirstBlock->m_ullOriginTime_us) / 1000) + 1 : 0;

   return m_iCount;
}

int CSndBuffer::dropLateData(int &bytes, uint64_t latetime)
{
   int dpkts = 0;
   int dbytes = 0;
   bool move = false;

   CGuard bufferguard(m_BufLock);
   for (int i = 0; i < m_iCount && m_pFirstBlock->m_ullOriginTime_us < latetime; ++ i)
   {
      dpkts++;
      dbytes += m_pFirstBlock->m_iLength;

      if (m_pFirstBlock == m_pCurrBlock) move = true;
      m_pFirstBlock = m_pFirstBlock->m_pNext;
   }
   if (move) m_pCurrBlock = m_pFirstBlock;
   m_iCount -= dpkts;

   m_iBytesCount -= dbytes;
   bytes = dbytes;

#ifdef SRT_ENABLE_SNDBUFSZ_MAVG
   updAvgBufSize(CTimer::getTime());
#endif /* SRT_ENABLE_SNDBUFSZ_MAVG */

// CTimer::triggerEvent();
   return(dpkts);
}

void CSndBuffer::increase()
{
   int unitsize = m_pBuffer->m_iSize;

   // new physical buffer
   Buffer* nbuf = NULL;
   try
   {
      nbuf  = new Buffer;
      nbuf->m_pcData = new char [unitsize * m_iMSS];
   }
   catch (...)
   {
      delete nbuf;
      throw CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0);
   }
   nbuf->m_iSize = unitsize;
   nbuf->m_pNext = NULL;

   // insert the buffer at the end of the buffer list
   Buffer* p = m_pBuffer;
   while (p->m_pNext != NULL)
      p = p->m_pNext;
   p->m_pNext = nbuf;

   // new packet blocks
   Block* nblk = NULL;
   try
   {
      nblk = new Block;
   }
   catch (...)
   {
      delete nblk;
      throw CUDTException(MJ_SYSTEMRES, MN_MEMORY, 0);
   }
   Block* pb = nblk;
   for (int i = 1; i < unitsize; ++ i)
   {
      pb->m_pNext = new Block;
      pb = pb->m_pNext;
   }

   // insert the new blocks onto the existing one
   pb->m_pNext = m_pLastBlock->m_pNext;
   m_pLastBlock->m_pNext = nblk;

   pb = nblk;
   char* pc = nbuf->m_pcData;
   for (int i = 0; i < unitsize; ++ i)
   {
      pb->m_pcData = pc;
      pb = pb->m_pNext;
      pc += m_iMSS;
   }

   m_iSize += unitsize;

   HLOGC(dlog.Debug, log << "CSndBuffer: BUFFER FULL - adding " << (unitsize*m_iMSS) << " bytes spread to " << unitsize << " blocks"
       << " (total size: " << m_iSize << " bytes)");

}

////////////////////////////////////////////////////////////////////////////////

/*
*   RcvBuffer (circular buffer):
*
*   |<----------------------- m_iSize ----------------------------->|
*   |       |<--- acked pkts -->|<-- m_iPastTailDelta -->|           |
*   |       |                   |                       |           |
*   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+   +---+
*   | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 | 1 | 1 | 0 |...| 0 | m_aUnits[]
*   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+   +---+
*             |                 | |               |
*             |                   |               \__last pkt received
*             |                   \___ m_iReadTail: last ack sent
*             \___ m_iReadHead: first message to read
*                      
*   m_aUnits[i]->status(): 0:free, 1:good, 2:passack, 3:dropped
* 
*   thread safety:
*    m_iReadHead:   CUDT::m_RecvLock 
*    m_iReadTail:   CUDT::m_AckLock 
*    m_iPastTailDelta:     CUDT::m_AckLock (intermediately, as addData is called under a lock already)
*/


// XXX Init values moved to in-class.
//const uint32_t CRcvBuffer::TSBPD_WRAP_PERIOD = (30*1000000);    //30 seconds (in usec)
//const int CRcvBuffer::TSBPD_DRIFT_MAX_VALUE   = 5000;  // usec
//const int CRcvBuffer::TSBPD_DRIFT_MAX_SAMPLES = 1000;  // ACK-ACK packets
#ifdef SRT_DEBUG_TSBPD_DRIFT
//const int CRcvBuffer::TSBPD_DRIFT_PRT_SAMPLES = 200;   // ACK-ACK packets
#endif


CRcvBuffer* CRcvBuffer::create(int size, int32_t last_skip_ack, bool live)
{
    HLOGC(mglog.Debug, log << "creating CRcvBuffer size=" << size
        << " tail-seq=" << last_skip_ack
        << " internal-ack=" << (live ? "IMMEDIATE" : "DEFERRED"));

    return new CRcvBuffer(size, last_skip_ack, live);
}


CRcvBuffer::CRcvBuffer(int bufsize, int32_t last_skip_ack, bool live):
m_aUnits(NULL),
m_iSize(bufsize),
m_iReadHead(0),
m_iReadTail(0),
m_iPastTailDelta(0),
m_iRefCount(1),
m_ReadTailSequence(last_skip_ack),
m_bImmediateAck(live),
m_iNotch(0)
,m_BytesCountLock()
,m_iBytesCount(0)
,m_iAckedPktsCount(0)
,m_iAckedBytesCount(0)
,m_iAvgPayloadSz(7*188)
,m_bTsbPdMode(false)
,m_uTsbPdDelay(0)
,m_ullTsbPdTimeBase(0)
,m_ullTsbPdTimeCarryover(0)
,m_bTsbPdWrapCheck(false)
//,m_iTsbPdDrift(0)
//,m_TsbPdDriftSum(0)
//,m_iTsbPdDriftNbSamples(0)
#ifdef SRT_ENABLE_RCVBUFSZ_MAVG
,m_LastSamplingTime(0)
,m_TimespanMAvg(0)
,m_iCountMAvg(0)
,m_iBytesCountMAvg(0)
#endif
{
   m_aUnits = new CUnit* [m_iSize];
   for (int i = 0; i < m_iSize; ++ i)
      m_aUnits[i] = NULL;

#ifdef SRT_DEBUG_TSBPD_DRIFT
   memset(m_TsbPdDriftHisto100us, 0, sizeof(m_TsbPdDriftHisto100us));
   memset(m_TsbPdDriftHisto1ms, 0, sizeof(m_TsbPdDriftHisto1ms));
#endif

   pthread_mutex_init(&m_BytesCountLock, NULL);
   pthread_mutex_init(&m_BufLock, NULL);
}

CRcvBuffer::~CRcvBuffer()
{
   for (int i = 0; i < m_iSize; ++ i)
   {
      if (m_aUnits[i] != NULL)
      {
          m_aUnits[i]->setFree();
      }
   }

   delete [] m_aUnits;

   pthread_mutex_destroy(&m_BufLock);
   pthread_mutex_destroy(&m_BytesCountLock);
}

void CRcvBuffer::countBytes(int pkts, int bytes, bool acked)
{
   /*
   * Byte counter changes from both sides (Recv & Ack) of the buffer
   * so the higher level lock is not enough for thread safe op.
   *
   * pkts are...
   *  added (bytes>0, acked=false),
   *  acked (bytes>0, acked=true),
   *  removed (bytes<0, acked=n/a)
   */
   CGuard cg(m_BytesCountLock);

   if (!acked) //adding new pkt in RcvBuffer
   {
       m_iBytesCount += bytes; /* added or removed bytes from rcv buffer */
       if (bytes > 0) /* Assuming one pkt when adding bytes */
          m_iAvgPayloadSz = ((m_iAvgPayloadSz * (100 - 1)) + bytes) / 100; 
   }
   else // acking/removing pkts to/from buffer
   {
       m_iAckedPktsCount += pkts; /* acked or removed pkts from rcv buffer */
       m_iAckedBytesCount += bytes; /* acked or removed bytes from rcv buffer */

       if (bytes < 0) m_iBytesCount += bytes; /* removed bytes from rcv buffer */
   }
}

int CRcvBuffer::addDataAt(int32_t sequence, CUnit* unit)
{
    // Guarding is for a case when the group receiving feature is used,
    // so potentially multiple CRcvQ:worker threads may try to call
    // this function at the same time. Locking is here otherwise not required.
    CGuard cg(m_BufLock);

    // Initial statement:
    //     HEAD                 TAIL     PAST   .... HEAD+MAXSIZE
    //      |                    |        |     ....    |
    //
    // SIZE = TAIL - HEAD = TAIL.seq - HEAD.seq
    // HEAD.seq = TAIL.seq - SIZE
    // MAX.seq = HEAD.seq + MAXSIZE

    // m_ReadTailSequence is the sequence number of the packet
    // stored at m_iReadTail. By decreasing it with the size of
    // the acknowledged range, we get the sequence at m_iReadHead.
    int head_sequence = CSeqNo::decseq(m_ReadTailSequence, getRcvDataSize());

    // So, this is the maximum sequence number that this may have.
    int max_sequence = CSeqNo::incseq(head_sequence, m_iSize);

    // Good. Now check if the sequence number is in the range:
    // <m_ReadTailSequence, max_sequence>
    //
    // That is, the sequence is between the moment when the packets
    // are acknowledged (packets already acked should be rejected anyway),
    // and the maximum position allowed by the buffer capacity.
    // To check the sequence range, we must compare the seqoff.

    int allowed_span = CSeqNo::seqoff(m_ReadTailSequence, max_sequence);
    int offset = CSeqNo::seqoff(m_ReadTailSequence, sequence);

    // Offset can be < 0 for lost packets, just must be within the existing
    // buffer range. This can go that far below 0 as for the head_sequence.
    int min_offset = -CSeqNo::seqoff(head_sequence, m_ReadTailSequence);

    HLOGC(dlog.Debug, log << "addDataAt: seq=" << sequence << " into RNG[" << head_sequence << "-" << m_ReadTailSequence << "..." << (m_ReadTailSequence + m_iPastTailDelta) << "]");

    if (offset < min_offset)
    {
        HLOGC(dlog.Debug, log << "Sequence number " << sequence << " is in the past (last ack: " << m_ReadTailSequence << ") - discarding");
        return -1;
    }

    if (offset > allowed_span)
    {
        int excess_span = CSeqNo::seqoff(m_ReadTailSequence, max_sequence + (m_iSize/2));
        if (offset > excess_span)
        {
            LOGC(dlog.Error, log << "Sequence number " << sequence << " is out of the current working range <"
                << m_ReadTailSequence << " ... " << max_sequence << "> with 1/2 size extra: RUNTIME ERROR or ATTACK");
        }
        else
        {
            LOGC(dlog.Error, log << "Packet with sequence=" << sequence << " can't be stored, buffer space depleted.");
        }
        return -1;
    }

    int result = addData(unit, offset);
    HLOGC(dlog.Debug, log << "addDataAt: UPDATED: RNG[" << head_sequence << "-" << m_ReadTailSequence << "..." << (m_ReadTailSequence + m_iPastTailDelta) << "] result:" << result);
    return result;
}

// Return value:
// -1: packet not stored (there already is a packet at that position)
// 0: packet stored, and it follows at least one existing packet
// 1: packet stored is a new head - supersedes the head or buffer was empty
// (head is the first good cell on HEAD-TAIL range)
/// (Internal) add the unit at position described by offset. The offset is
/// calculated initially as a distance between the sequence number in the packet
/// and the sequence number cached in @a m_ReadTailSequence, which is the
/// sequence of the packet stored at @a m_iReadTail - so it's simultaneously
/// a distance towards @a m_iReadTail.
/// @param unit Unit to be stored (containing a packet)
/// @param offset Position towards the @a m_iReadTail
/// @retval -1 This position is already covered, so packet was not stored.
/// @retval 0 Packet stored, and at least one packet in the buffer is at earlier position
/// @retval 1 Packet stored, and it's a new head (earliest position)
int CRcvBuffer::addData(CUnit* unit, int offset)
{
    // Get the place predicted for given sequence
    int pos = shift(m_iReadTail, offset);
    if (m_aUnits[pos] != NULL)
    {
        HLOGP(dlog.Debug, "addData: there is a packet already at that position");
#if ENABLE_LOGGING
        // Make a sanity check here. The condition to check if the offset exceeds
        // m_iPastTailDelta was before this condition earlier, however if it
        // has ever happened that there is a valid packet stored at the position
        // that HAS NOT BEEN READ TO EVER BEFORE, then there's something really wrong here.
        if (offset >= m_iPastTailDelta)
        {
            LOGP(dlog.Fatal, "INCOMING PACKET offset EXCEEDS the non-contiguous range and found an existing packet there");
            // This is a change: in this case, leave the past-tail-delta unchanged.
            // Not sure what should be done in this case, however.
        }
#endif
        return -1;
    }

    // Update position at which it was placed.
    // ReadTail doesn't change the position here.
    int new_head_status = 0;
    if (empty())
    {
        LOGP(dlog.Debug, "addData: WILL NEED SIGNAL because this is the first packet");
        new_head_status = 1;
    }

    // NOTE: empty() and the below condition MIGHT be satisfied as either of or both simultaneously.
    if (offset >= m_iPastTailDelta)
    {
        // Subsequent packet.
        m_iPastTailDelta = offset + 1;
    }
    else if (m_bImmediateAck && new_head_status == 0)
    {
        // Packet recovered. Unless:
        // - "packet contiguousness ACK" method is by-sent-ack (in contradiction to immediate)
        //   - the check for it is deferred to the moment when UMSG_ACK is to be sent
        // - the packet to be newly inserted is the only packet in the buffer
        //   - then we already know that it's a head-ahead (and becomes a new head)
        //
        // Otherwise check if between the cell of a newly inserted packet and the end
        // of the so far contiguous range (HEAD-TAIL) there is any good cell.

        for (int d = offset+1; d < m_iPastTailDelta; ++d)
        {
            int p = shift(m_iReadTail, d);
            if (m_aUnits[p] && m_aUnits[p]->status() == CUnit::GOOD)
            {
                // If we have a situation that the sequence of the packet
                // to be inserted is EARLIER than the head-ahead packet,
                // it becomes this way a new head-ahead packet. This causes
                // returning 1 here to declare that the TSBPD condition
                // must be signaled because it is probably currently sleeping
                // with either timeout set to the old head-ahead packet,
                // or indefinitely, that is, it expects to be woken up on
                // a signal from here.
                new_head_status = 1;
                LOGP(dlog.Debug, "addData: WILL NEED SIGNAL because it's new head");
                break;
            }
        }
    }

    m_aUnits[pos] = unit;
    countBytes(1, unit->ref_packet().getLength());

    unit->setGood();

    if (m_bImmediateAck)
    {
        ackContiguous();
    }
    else
    {
        HLOGC(dlog.Debug, log << "addData: NOT acknowledging packets internally - will be done when sending UMSG_ACK");
    }

    return new_head_status;
}

void CRcvBuffer::ackContiguous()
{
    // This is done immediately after adding a packet.
    int bytes = 0;

    // Start with the position of past-the-end of the contiguous range.
    // Ride up to the m_iPastTailDelta, stopping on the first non-contiguous.
    // The position at m_iReadTail + m_iPastTailDelta should be obviously
    // lacking, but the new position of m_iReadTail should be at the first
    // empty cell.

    int read_tail = m_iReadTail;
    int ack_delta = 0;
    for (; ack_delta < m_iPastTailDelta; ++ack_delta, read_tail = shift_forward(read_tail))
    {
        // Just a while ago there was added a packet,
        // either at the position m_iPastTailDelta-1 (fresh),
        // or next to m_iReadTail. Start from m_iReadTail
        // and check packets up to m_iPastTailDelta if all
        // of them are contiguous. When a lacking packet found,
        // then acknowledge only up to this one.
        if (m_aUnits[read_tail] && m_aUnits[read_tail]->status() == CUnit::GOOD)
        {
            bytes += m_aUnits[read_tail]->ref_packet().getLength();
        }
        else
        {
            break;
        }
    }

#if ENABLE_HEAVY_LOGGING
    int base = CSeqNo::incseq(m_ReadTailSequence, 1);
    int end = CSeqNo::incseq(m_ReadTailSequence, ack_delta);

    HLOGC(mglog.Debug, log << "ackContiguous: to be clipped: from=" << base << " to=" << end);
#endif

    // If the loop didn't catch any empty cell, then at exit d == m_iPastTailDelta.

    // This will be 0, if the above loop found a lacking packet already
    // at the [0] position.
    if (ack_delta > 0)
    {
        countBytes(ack_delta, bytes, true);

        // Update pointers
        m_iPastTailDelta -= ack_delta;
        m_iReadTail = read_tail; // ATOMIC, but it's under a lock already anyway
        m_ReadTailSequence = CSeqNo::incseq(m_ReadTailSequence, ack_delta);

        CTimer::triggerEvent();
    }
}

int CRcvBuffer::readBuffer(char* data, int len)
{
   int p = m_iReadHead;
   int lastack = m_iReadTail;
   int rs = len;
#if ENABLE_HEAVY_LOGGING
   char* begin = data;
#endif

   uint64_t now = (m_bTsbPdMode ? CTimer::getTime() : 0LL);

   HLOGC(dlog.Debug, log << CONID() << "readBuffer: start=" << p << " lastack=" << lastack);
   while ((p != lastack) && (rs > 0))
   {
      if (m_bTsbPdMode)
      {
          HLOGC(dlog.Debug, log << CONID() << "readBuffer: chk if time2play: NOW=" << now << " PKT TS=" << getPktTsbPdTime(m_aUnits[p]->ref_packet().getMsgTimeStamp()));
          if ((getPktTsbPdTime(m_aUnits[p]->ref_packet().getMsgTimeStamp()) > now))
              break; /* too early for this unit, return whatever was copied */
      }

      int unitsize = m_aUnits[p]->ref_packet().getLength() - m_iNotch;
      if (unitsize > rs)
         unitsize = rs;

      HLOGC(dlog.Debug, log << CONID() << "readBuffer: copying buffer #" << p
          << " targetpos=" << int(data-begin) << " sourcepos=" << m_iNotch << " size=" << unitsize << " left=" << (unitsize-rs));
      memcpy(data, m_aUnits[p]->ref_packet().m_pcData + m_iNotch, unitsize);
      data += unitsize;

      if ((rs > unitsize) || (rs == int(m_aUnits[p]->ref_packet().getLength()) - m_iNotch))
      {
          freeUnitAt(p);
          p = shift_forward(p);

          m_iNotch = 0;
      }
      else
         m_iNotch += rs;

      rs -= unitsize;
   }

   /* we removed acked bytes form receive buffer */
   countBytes(-1, -(len - rs), true);
   m_iReadHead = p;

   return len - rs;
}

int CRcvBuffer::readBufferToFile(fstream& ofs, int len)
{
   int p = m_iReadHead;
   int lastack = m_iReadTail;
   int rs = len;

   while ((p != lastack) && (rs > 0))
   {
      int unitsize = m_aUnits[p]->ref_packet().getLength() - m_iNotch;
      if (unitsize > rs)
         unitsize = rs;

      ofs.write(m_aUnits[p]->ref_packet().m_pcData + m_iNotch, unitsize);
      if (ofs.fail())
         break;

      if ((rs > unitsize) || (rs == int(m_aUnits[p]->ref_packet().getLength()) - m_iNotch))
      {
          freeUnitAt(p);

          p = shift_forward(p);

          m_iNotch = 0;
      }
      else
         m_iNotch += rs;

      rs -= unitsize;
   }

   /* we removed acked bytes form receive buffer */
   countBytes(-1, -(len - rs), true);
   m_iReadHead = p;

   return len - rs;
}

bool CRcvBuffer::ackDataTo(int32_t upseq)
{
    if (upseq < 0)
        return false;

    bool updated = false;

    CGuard bl(m_BufLock);

    int acksize = CSeqNo::seqoff(m_ReadTailSequence, upseq);
    if (acksize > 0)
    {
        HLOGC(dlog.Debug, log << "ackDataTo: ACKing seq: " << m_ReadTailSequence
            << " - " << upseq << " (" << acksize << " packets)");
        ackData(acksize);
        updated = true;
    }
    m_ReadTailSequence = upseq;
    return updated;
}

void CRcvBuffer::ackData(int len)
{
    // Move the m_iReadTail position further by 'len'.
    // This is done regardless if there are units on that position, although
    // the primary statement is that the range between m_iReadHead and
    // m_iReadTail is perfectly contiguous. This might not be true in case
    // when 'skipData' was called and therefore packets at positions where the
    // unit is lacking are intentionally dropped.

    // This actually declares more packets that are considered ACK-ed
    // and therefore available for in-order reading.

    int pkts = 0;
    int bytes = 0;

    // for (i: m_iReadTail ... m_iReadTail +% len)
    int i_end = shift(m_iReadTail, len);
    for (int i = m_iReadTail; i != i_end; i = shift(i, 1))
    {
        if (m_aUnits[i]) // have something there
        {
            pkts++;
            bytes += m_aUnits[i]->ref_packet().getLength();
        }
    }
    if (pkts > 0)
    {
        countBytes(pkts, bytes, true);
    }
    m_iReadTail = i_end;
    m_iPastTailDelta -= len;
    if (m_iPastTailDelta < 0)
        m_iPastTailDelta = 0;

    CTimer::triggerEvent();
}

int CRcvBuffer::skipDataTo(int32_t upseq)
{
    if (upseq == -1) // nothing to skip
        return 0;

    CGuard bl(m_BufLock);

    int seqlen = CSeqNo::seqoff(m_ReadTailSequence, upseq);
    if (seqlen > 0)
        skipData(seqlen);
    m_ReadTailSequence = upseq;
    return seqlen;
}

void CRcvBuffer::skipData(int len)
{
    /* 
     * Caller need protect both AckLock and RecvLock
     * to move both m_iReadHead and m_iReadTail
     */

    // This shifts FOA m_iReadTail by 'len'. If the buffer was empty, shift
    // also m_iReadHead to the position of m_iReadTail (to keep it empty),
    // otherwise there are some remaining data to be read from the buffer.

    // If the buffer wasn't empty, but there are still empty cells
    // in the HEAD-TAIL range, this range is still considered contiguous.

    bool empty = m_iReadHead == m_iReadTail;
    m_iReadTail = shift(m_iReadTail, len);
    if (empty)
        m_iReadHead = m_iReadTail;

    // The m_iPastTailDelta must stay where it is (delta to be decreased by the
    // length), unless the m_iReadTail is to be set further than that, in which
    // case it should also keep its position (delta to be set 0).

    m_iPastTailDelta -= len;
    if (m_iPastTailDelta < 0)
    {
        m_iPastTailDelta = 0;
    }
    else
    {
        // In case when there are still some packets "ahead of tail",
        // try to internal-ACK them if they are contiguous
        if (m_bImmediateAck)
            ackContiguous();
    }
}

#if ENABLE_HEAVY_LOGGING
inline bool whichcond(bool cond, std::string& variable, std::string value)
{
    if (cond)
        variable = value;
    return cond;
}
#else
inline bool whichcond(bool x, std::string&, std::string) {return x;}
#endif

bool CRcvBuffer::getFirstAvailMsg(ref_t<uint64_t> r_playtime, ref_t<int32_t> r_pktseq, ref_t<bool> r_skipping)
{
    // Start with finding something in the receive-ready range.

    // First, LOCK at the current end of range. Any shifts done by another
    // thread will only move it forward, so worst case scenario, it will not
    // report a packet, if any was added in the meantime.
    int read_tail = m_iReadTail;
#if ENABLE_HEAVY_LOGGING
    int starting_head = m_iReadHead;
#endif

    *r_skipping = false;
    *r_playtime = 0;
    *r_pktseq = -1;

    int rmpkts = 0;
    int rmbytes = 0;
    bool empty = true;

    // Delete all cells that are invalid or contain bad cell (delete the latter as well).
    // No such cells should be here, but well, various things may happen, so this is a sanity check.
    for ( ; m_iReadHead != read_tail; m_iReadHead = shift_forward(m_iReadHead))
    {
        empty = false;
        if (m_aUnits[m_iReadHead] == NULL)
        {
#if ENABLE_HEAVY_LOGGING
            int head_seq = CSeqNo::decseq(m_ReadTailSequence, getRcvDataSize());
            LOGC(dlog.Error, log << "getFirstAvailMsg: IPE: non-contiguous cell found at seq="
                << head_seq << " - skipping this sequence");
#endif
            continue;
        }

        std::string reason;
        if ( whichcond(m_aUnits[m_iReadHead]->status() != CUnit::GOOD, reason, "BAD UNIT")
                || whichcond(m_aUnits[m_iReadHead]->ref_packet().getMsgCryptoFlags() != EK_NOENC, reason, "DECRYPTION FAILED"))
        {
#if ENABLE_HEAVY_LOGGING
            int head_seq = CSeqNo::decseq(m_ReadTailSequence, getRcvDataSize());
            LOGC(dlog.Error, log << "getFirstAvailMsg: WRONG STATUS for cell found at seq="
                << head_seq << " (" << reason << ") - skipping this sequence");
#endif
            rmpkts++;
            rmbytes += freeUnitAt(m_iReadHead);
            continue;
        }

        // First cell that does not satisfy this "bad" condition is good.
        // Stop stripping the buffer here.
#if ENABLE_HEAVY_LOGGING

        // Don't send misleading "skipping" log
        if (m_iReadHead != starting_head)
            HLOGC(dlog.Debug, log << "getFirstAvailMsg: ... skipped bad cells up to seq=" << m_aUnits[m_iReadHead]->ref_packet().getSeqNo());
#endif
        break;
    }

    countBytes(-rmpkts, -rmbytes, true);

    // Now the serious part. Check if the HEAD-TAIL range contains anything.
    if (m_iReadHead != read_tail)
    {
        // Good, so we have at least one valid packet at the head.
        // Note that HEAD-TAIL range is meant to be contiguous, so this
        // really is the subsequent packet.
        // Still no need to lock the buffer yet, we are moving in the area
        // not used by the CRcvQ:worker thread(s).
        *r_skipping = false; // if these above skipped anything, it's skipped already.
        CPacket& pkt = m_aUnits[m_iReadHead]->ref_packet();
        *r_playtime = getPktTsbPdTime(pkt.getMsgTimeStamp());
        *r_pktseq = pkt.getSeqNo();

        // Whether ready to play or not, we are yet about to check, though.
        int64_t towait = (*r_playtime - CTimer::getTime());
        if (towait > 0) // TSBPD-time is in future
        {
            HLOGC(mglog.Debug, log << "getFirstAvailMsg: packet (CTG) seq=" << r_pktseq.get()
                << " NOT ready to play (only in " << (towait/1000.0) << "ms) PTS="
                << logging::FormatTime(*r_playtime));
            return false;
        }

        HLOGC(mglog.Debug, log << "getFirstAvailMsg: packet (CTG) seq=" << r_pktseq.get()
            << " ready to play (delayed " << (-towait/1000.0) << "ms) PTS="
            << logging::FormatTime(*r_playtime));

        return true;
    }

    // ----------
    //
    // The above procedure is done without locking for performance reasons, and
    // MOST OF THE TIME (except the first packet ever, or first packet after after
    // a longer pause) in the Live mode the above procedure WILL return something.
    //
    // After making sure that this above procedure did not extract the next packet,
    // we try now with locking.
    // -----------

    // Effectively, the position where read_tail was standing was pointing
    // to the past-the-end of a contiguous buffer. The cell currently
    // pointed by 'read_tail', after locking, is one of:
    // - nothing (if read_tail == m_iReadTail and m_iPastTailDelta == 0)
    // - an empty cell, possibly followed by a good cell in perspective somewhere
    // - a good cell, in case when some other thread has added this cell
    //   in the meantime (either by a recovered lost packet, or receiving a
    //   subsequent packet).

    // | ? | 0 | 0 | 1 | 0 |
    //   |   \_          \_____m_iPastTailDelta
    //   |      - m_iReadTail
    // read_tail

    // So now embrace the range <read_tail ... m_iReadTail + m_iPastTailDelta).

    // The contiguous range is empty, check if you have anything.
    // Note that with some probability it is possible that at this moment
    // read_tail != m_iReadTail. Don't worry about it. Treat this range
    // as a part of non-contiguous range; when the caller realizes that
    // we declared packets to skip, but the skip range is empty at that moment,
    // it will simply do nothing to skip the packets, that's all.

    // But here we are working on a non-contiguous range, which is used by
    // CRcvQ:worker threads, so locking is here necessary. Don't change the
    // working range though because otherwise the above conditions that are
    // taken as a good deal here, would be false.

    *r_playtime = 0; // Initially, for a case when nothing was found anyway

    CGuard lk(m_BufLock);

    // Use m_iReadTail here (not read_tail) because the m_iPastTailDelta is
    // a value which is a shift towards m_iReadTail and is updated in synch with it.
    int end_range = shift(m_iReadTail, m_iPastTailDelta);

    // PSEUDO-CODE with C++ high level defs:
    //
    //      pkt_pos = find_if(read_tail, end_range,
    //                       [](auto& unit) {
    //                          return !unit
    //                              || unit->status() != GOOD
    //                              || unit->pkt->cryptoFlags != EK_NOENC
    //                       });

    *r_skipping = false; // YET
#if ENABLE_HEAVY_LOGGING
    std::string contig = empty ? "(EMPTY)" : "(NON-CTG)"; // so far
#endif

    if (read_tail == m_iReadTail)
    {
        *r_skipping = true;
#if ENABLE_HEAVY_LOGGING
        contig = "(CTG,fixed)";
#endif
    }
    else
    {
#if ENABLE_HEAVY_LOGGING
        int dist = m_iReadTail - read_tail;
        if (dist < 0)
            dist += m_iSize;
        int32_t old_seq = CSeqNo::decseq(m_ReadTailSequence, dist);
        HLOGC(dlog.Debug, log << "(shifted in the meantime: old=" << old_seq << " new=" << m_ReadTailSequence << ")");
#endif
    }

    for (int i = read_tail; i != end_range; i = shift_forward(i))
    {
        // In "normally expected condition", this below will fire
        // ALWAYS at the very first iteration. In case of a very
        // supernatural situation that m_iReadTail has been shifted
        // "behind the back" of this function (before the lock was applied),
        // this will NOT be done, and it will hit the jackpot at
        // the first iteration (so it won't have any opportunity to
        // check it later). Of course, here it's already under
        // a lock, so m_iReadTail will stay unchanged now, so just
        // don't provide a false information of "skip required" if
        // it occasionally provides a contiguous sequence.
        if (!m_aUnits[i])
        {
            continue; // no cell here
        }

        if (m_aUnits[i]->status() != CUnit::GOOD)
        {
            continue; // bad cell
        }

        if (m_aUnits[i]->ref_packet().getMsgCryptoFlags() != EK_NOENC)
        {
            continue; // not decrypted
        }

        // JACKPOT. This loop will be broken here.

        // Ok, we have the first valid packet in the range.
        CPacket& pkt = m_aUnits[i]->ref_packet();
        *r_playtime = getPktTsbPdTime(pkt.getMsgTimeStamp());
        *r_pktseq = pkt.getSeqNo();

        // Whether ready to play or not, we are yet about to check, though.
        int64_t towait = (*r_playtime - CTimer::getTime());
        if (towait > 0) // TSBPD-time is in future
        {
            HLOGC(mglog.Debug, log << "getFirstAvailMsg: packet " << contig
                << " seq=" << r_pktseq.get() << " NOT ready to play (only in "
                << (towait/1000.0) << "ms) PTS="
                << logging::FormatTime(*r_playtime));
            return false;
        }

        HLOGC(mglog.Debug, log << "getFirstAvailMsg: packet " << contig
            << " seq=" << r_pktseq.get() << " ready to play (delayed "
            << (-towait/1000.0) << "ms) PTS="
            << logging::FormatTime(*r_playtime));
        return true;
    }

    // Reached the end and nothing found. Or not even started looping here.

    // (don't specify whether you don't have EUR, USD or CAD, simply say "dire straits")
    HLOGC(mglog.Debug, log << "getFirstAvailMsg: no packets in the receiving buffer AT ALL.");
    return false;
}

bool CRcvBuffer::getRcvFirstMsg(ref_t<uint64_t> r_tsbpdtime, ref_t<bool> r_passack, ref_t<int32_t> r_skipseqno, ref_t<int32_t> r_curpktseq)
{
    int32_t& skipseqno = *r_skipseqno;
    bool& passack = *r_passack;
    skipseqno = -1;
    passack = false;
    // tsbpdtime will be retrieved by the below call
    // Returned values:
    // - tsbpdtime: real time when the packet is ready to play (whether ready to play or not)
    // - passack: false (the report concerns a packet with an exactly next sequence)
    // - skipseqno == -1: no packets to skip towards the first RTP
    // - curpktseq: sequence number for reported packet (for debug purposes)
    // - @return: ready (to play) or not

    /* Check the acknowledged packets */

    // getRcvReadyMsg returns true if the time to play for the first message
    // (returned in r_tsbpdtime) is in the past.
    if (getRcvReadyMsg(r_tsbpdtime, r_curpktseq))
    {
        return true;
    }
    else if (*r_tsbpdtime != 0)
    {
        // This means that a message next to be played, has been found,
        // but the time to play is in future.
        return false;
    }

    // getRcvReadyMsg returned false and tsbpdtime == 0.

    // Below this line we have only two options:
    // - m_iPastTailDelta == 0, which means that no more packets are in the buffer
    //    - returned: tsbpdtime=0, passack=true, skipseqno=-1, curpktseq=0, @return false
    // - m_iPastTailDelta > 0, which means that there are packets arrived after a lost packet:
    //    - returned: tsbpdtime=PKT.TS, passack=true, skipseqno=PKT.SEQ, ppkt=PKT, @return LOCAL(PKT.TS) <= NOW
    //
    // (note: the "passack" range from this architecture point of view are simply packets for
    //  which the UMSG_ACK wasn't yet sent; as in case of live mode packets get ACK-ed quickly,
    //  it can be approximated that the first packet in the "passack" range is missing).

    /* 
     * No acked packets ready but caller want to know next packet to wait for
     * Check the not yet acked packets that may be stuck by missing packet(s).
     */
    bool haslost = false;
    *r_tsbpdtime = 0; // redundant, for clarity
    passack = true;

    // XXX SUSPECTED ISSUE with this algorithm:
    // The above call to getRcvReadyMsg() should report as to whether:
    // - there is an EXACTLY NEXT SEQUENCE packet
    // - this packet is ready to play.
    //
    // Situations handled after the call are when:
    // - there's the next sequence packet available and it is ready to play
    // - there are no packets at all, ready to play or not
    //
    // So, the remaining situation is that THERE ARE PACKETS that follow
    // the current sequence, but they are not ready to play. This includes
    // packets that have the exactly next sequence and packets that jump
    // over a lost packet.
    //
    // As the getRcvReadyMsg() function walks through the incoming units
    // to see if there's anything that satisfies these conditions, it *SHOULD*
    // be also capable of checking if the next available packet, if it is
    // there, is the next sequence packet or not. Retrieving this exactly
    // packet would be most useful, as the test for play-readiness and
    // sequentiality can be done on it directly.
    //
    // When done so, the below loop would be completely unnecessary.

    // Logical description of the below algorithm:
    // 1. Check if the VERY FIRST PACKET is valid; if so then:
    //    - check if it's ready to play, return boolean value that marks it.

    for (int i = m_iReadTail, n = shift(m_iReadTail, m_iPastTailDelta); i != n; i = shift_forward(i))
    {
        if ( !m_aUnits[i] || m_aUnits[i]->status() != CUnit::GOOD )
        {
            /* There are packets in the sequence not received yet */
            haslost = true;
        }
        else
        {
            /* We got the 1st valid packet */
            *r_tsbpdtime = getPktTsbPdTime(m_aUnits[i]->ref_packet().getMsgTimeStamp());
            if (*r_tsbpdtime <= CTimer::getTime())
            {
                /* Packet ready to play */
                if (haslost)
                {
                    /* 
                     * Packet stuck on non-acked side because of missing packets.
                     * Tell 1st valid packet seqno so caller can skip (drop) the missing packets.
                     */
                    skipseqno = m_aUnits[i]->ref_packet().m_iSeqNo;
                    *r_curpktseq = skipseqno;
                }

                // NOTE: if haslost is not set, it means that this is the VERY FIRST
                // packet, that is, packet currently at pos = m_iReadTail. There's no
                // possibility that it is so otherwise because:
                // - if this first good packet is ready to play, THIS HERE RETURNS NOW.
                // ...
                return true;
            }
            // ... and if this first good packet WASN'T ready to play, THIS HERE RETURNS NOW, TOO,
            // just states that there's no ready packet to play.
            // ...
            return false;
        }
        // ... and if this first packet WASN'T GOOD, the loop continues, however since now
        // the 'haslost' is set, which means that it continues only to find the first valid
        // packet after stating that the very first packet isn't valid.
    }
    return false;
}

bool CRcvBuffer::getRcvReadyMsg(ref_t<uint64_t> r_tsbpdtime, ref_t<int32_t> r_curpktseq)
{
    *r_tsbpdtime = 0;
    int rmpkts = 0;
    int rmbytes = 0;

    string reason = "NOT RECEIVED";

    // Lock at this value for a case when in the meantime some other thread
    // has ADDED some new packets. Actually this function should be called in
    // response to a signal that says that a new packet arrived, AFTER it did.
    // But it's possible that some new packets have arrived also in the meantime.

    // There's nothing dangerous with reading it; worst case scenario, this
    // "tail" will be shifted "down the buffer", that is, some of the packets
    // that are already there in the meantime when this function is checking,
    // will not be taken into account THIS TIME.
    int read_tail = m_iReadTail;

    for (int i = m_iReadHead, n = read_tail; i != n; i = shift_forward(i))
    {
        /* Skip any invalid skipped/dropped packets */

        // NOTE: according to the way how this functions in case of TSBPD
        // and live mode, this should be impossible because:

        // 1. If empty buffer (m_iReadHead == m_iReadTail), this loop will not execute.
        // 2. If there happened a situation that m_iReadTail was shifted, it could
        // only be done as:
        // - a result of received ACKACK, if file mode is used (until then the 
        //   newly arrived packets stay past the m_iReadTail position, even if they
        //   are contiguous). When this happens, m_iReadTail is only shifted up to
        //   the position of the first lost packet, that is, after this shift all
        //   packets in this range are contiguous (m_aUnits[i] != NULL).
        // - just after adding a new packet to the buffer, in live mode (m_bImmediateAck)
        //   the m_iReadTail pointer is moved up to the first lost packet, or up to
        //   the position pointed by m_iPastTailDelta.
        // 3. If the TLPKTDROP situation happens, the skipData() function is called,
        //    which starts with the situation that m_iReadHead == m_iReadTail (the cell
        //    at that position == NULL because it's a lost packet), and exits with
        //    the situation that there's at least one packet in this range, and again,
        //    all packets in the head-tail range are contiguous.
        //
        // Result: this is only a sanity check and this condition should
        // not be possible to happen.
        if (m_aUnits[i] == NULL)
        {
#if ENABLE_HEAVY_LOGGING
            int head_seq = CSeqNo::decseq(m_ReadTailSequence, getRcvDataSize());
            LOGC(mglog.Error, log << "rcv buffer: IPE: non-contiguous cell found at seq=" << head_seq << " - skipping this sequence");
#endif
            m_iReadHead = shift_forward(m_iReadHead);
            continue;
        }

        if (m_aUnits[i]->status() != CUnit::GOOD || m_aUnits[i]->ref_packet().getMsgCryptoFlags() != EK_NOENC)
        {
#if ENABLE_HEAVY_LOGGING
            int head_seq = CSeqNo::decseq(m_ReadTailSequence, getRcvDataSize());
            LOGC(mglog.Error, log << "rcv buffer: IPE: WRONG STATUS for cell found at seq=" << head_seq << " - skipping this sequence");
#endif
            rmpkts++;
            rmbytes += freeUnitAt(i);
            m_iReadHead = shift_forward(m_iReadHead);
            continue;
        }

        *r_curpktseq = m_aUnits[i]->ref_packet().getSeqNo();
        *r_tsbpdtime = getPktTsbPdTime(m_aUnits[i]->ref_packet().getMsgTimeStamp());

        int64_t towait = (*r_tsbpdtime - CTimer::getTime());
        if (towait > 0)
        {
            HLOGC(mglog.Debug, log << "getRcvReadyMsg: packet seq=" << r_curpktseq.get() << " NOT ready to play (only in " << (towait/1000.0) << "ms)");
            return false;
        }

        HLOGC(mglog.Debug, log << "getRcvReadyMsg: packet seq=" << r_curpktseq.get() << " ready to play (delayed " << (-towait/1000.0) << "ms)");
        return true;
    }

    HLOGC(mglog.Debug, log << "getRcvReadyMsg: nothing to deliver: " << reason);
    /* removed skipped, dropped, undecryptable bytes from rcv buffer */
    countBytes(-rmpkts, -rmbytes, true);
    return false;
}


/*
* Return receivable data status (packet timestamp ready to play if TsbPd mode)
* Return playtime (tsbpdtime) of 1st packet in queue, ready to play or not
*
* Return data ready to be received (packet timestamp ready to play if TsbPd mode)
* Using getRcvDataSize() to know if there is something to read as it was widely
* used in the code (core.cpp) is expensive in TsbPD mode, hence this simpler function
* that only check if first packet in queue is ready.
*/
bool CRcvBuffer::isRcvDataReady(ref_t<uint64_t> tsbpdtime, ref_t<int32_t> curpktseq)
{
   *tsbpdtime = 0;

   if (m_bTsbPdMode)
   {
       CPacket* pkt = getRcvReadyPacket();
       if ( pkt )
       {
            /* 
            * Acknowledged data is available,
            * Only say ready if time to deliver.
            * Report the timestamp, ready or not.
            */
            *curpktseq = pkt->getSeqNo();
            *tsbpdtime = getPktTsbPdTime(pkt->getMsgTimeStamp());
            if (*tsbpdtime <= CTimer::getTime())
               return true;
       }
       return false;
   }

   return isRcvDataAvailable();
}

// XXX This function may be called only after checking
// if m_bTsbPdMode.
CPacket* CRcvBuffer::getRcvReadyPacket()
{
    for (int i = m_iReadHead, n = m_iReadTail; i != n; i = shift(i, 1))
    {
        /* 
         * Skip missing packets that did not arrive in time.
         */
        if ( m_aUnits[i] && m_aUnits[i]->status() == CUnit::GOOD )
            return &m_aUnits[i]->ref_packet();
    }

    return 0;
}

bool CRcvBuffer::isRcvDataReady()
{
   uint64_t tsbpdtime;
   int32_t seq;

   return isRcvDataReady(Ref(tsbpdtime), Ref(seq));
}

int CRcvBuffer::getAvailBufSize() const
{
   // One slot must be empty in order to tell the difference between "empty buffer" and "full buffer"
   return m_iSize - getRcvDataSize() - 1;
}

int CRcvBuffer::getRcvDataSize() const
{
    // Prevent wrong results around non-atomic access
    int read_head = m_iReadHead, read_tail = m_iReadTail;

    if (read_tail >= read_head)
        return read_tail - read_head;

    return m_iSize + read_tail - read_head;
}

int CRcvBuffer::debugGetSize() const
{
    // Does exactly the same as getRcvDataSize, but
    // it should be used FOR INFORMATIONAL PURPOSES ONLY.
    // The source values might be changed in another thread
    // during the calculation, although worst case the
    // resulting value may differ to the real buffer size by 1.
    int from = m_iReadHead, to = m_iReadTail;
    int size = to - from;
    if (size < 0)
        size += m_iSize;

    return size;
}


bool CRcvBuffer::empty() const
{
    // This will not always return the intended value,
    // that is, it may return false when the buffer really is
    // empty - but it will return true then in one of next calls.
    // This function will be always called again at some point
    // if it returned false, and on true the connection
    // is going to be broken - so this behavior is acceptable.
    return m_iReadHead == m_iReadTail;
}


#ifdef SRT_ENABLE_RCVBUFSZ_MAVG

#define SRT_MAVG_BASE_PERIOD 1000000 // us
#define SRT_us2ms 1000

/* Return moving average of acked data pkts, bytes, and timespan (ms) of the receive buffer */
int CRcvBuffer::getRcvAvgDataSize(int &bytes, int &timespan)
{
   timespan = m_TimespanMAvg;
   bytes = m_iBytesCountMAvg;
   return(m_iCountMAvg);
}

/* Update moving average of acked data pkts, bytes, and timespan (ms) of the receive buffer */
void CRcvBuffer::updRcvAvgDataSize(uint64_t now)
{
   uint64_t elapsed = (now - m_LastSamplingTime) / SRT_us2ms; //ms since last sampling

   if (elapsed < (SRT_MAVG_BASE_PERIOD / SRT_MAVG_SAMPLING_RATE) / SRT_us2ms)
      return; /* Last sampling too recent, skip */

   if (elapsed > SRT_MAVG_BASE_PERIOD)
   {
      /* No sampling in last 1 sec, initialize/reset moving average */
      m_iCountMAvg = getRcvDataSize(m_iBytesCountMAvg, m_TimespanMAvg);
      m_LastSamplingTime = now;

      HLOGF(dlog.Debug, "updRcvAvgDataSize: RESET SAMPLING. %6dp %6dB span=%6dms long sampledist=%5llums\n", m_iCountMAvg, m_iBytesCountMAvg, m_TimespanMAvg, (unsigned long long)elapsed);
   }
   else if (elapsed >= (SRT_MAVG_BASE_PERIOD / SRT_MAVG_SAMPLING_RATE) / SRT_us2ms)
   {
      /*
      * Weight last average value between -1 sec and last sampling time (LST)
      * and new value between last sampling time and now
      *                                      |elapsed|
      *   +----------------------------------+-------+
      *  -1                                 LST      0(now)
      */
      int instspan;
      int bytescount;
      int count = getRcvDataSize(bytescount, instspan);

      m_iCountMAvg      = (int)(((count      * (1000 - elapsed)) + (count      * elapsed)) / 1000);
      m_iBytesCountMAvg = (int)(((bytescount * (1000 - elapsed)) + (bytescount * elapsed)) / 1000);
      m_TimespanMAvg    = (int)(((instspan   * (1000 - elapsed)) + (instspan   * elapsed)) / 1000);
      m_LastSamplingTime = now;

      HLOGF(dlog.Debug, "updRcvAvgDataSize: SAMPLE PERIOD. %6dp %6dB %6dms sampledist=%5llums\n", count, bytescount, instspan, (unsigned long long)elapsed);
   }
}
#endif /* SRT_ENABLE_RCVBUFSZ_MAVG */

/* Return acked data pkts, bytes, and timespan (ms) of the receive buffer */
int CRcvBuffer::getRcvDataSize(int &bytes, int &timespan)
{
   timespan = 0;
   if (m_bTsbPdMode)
   {
      /* skip invalid entries */
      int i,n;
      for (i = m_iReadHead, n = m_iReadTail; i != n; i = shift(i, 1))
      {
         if (m_aUnits[i] && m_aUnits[i]->status() == CUnit::GOOD)
             break;
      }

      /* Get a valid startpos */
      int startpos = i;
      int endpos = n;

      if (m_iReadTail != startpos)
      {
         /*
         *     |<--- DataSpan ---->|<- m_iPastTailDelta ->|
         * +---+---+---+---+---+---+---+---+---+---+---+---
         * |   | 1 | 1 | 1 | 0 | 0 | 1 | 1 | 0 | 1 |   |     m_aUnits[]
         * +---+---+---+---+---+---+---+---+---+---+---+---
         *       |                   |
         *       \_ m_iReadHead      \_ m_iReadTail
         *        
         * m_pUnits[startpos] shall be valid (->status()==CUnit::GOOD).
         * If m_pUnits[m_iReadTail-1] is not valid (NULL or ->status()!=CUnit::GOOD), 
         * it means m_pUnits[m_iReadTail] is valid since a valid unit is needed to skip.
         * Favor m_pUnits[m_iReadTail] if valid over [m_iReadTail-1] to include the whole acked interval.
         */
         if ((m_iPastTailDelta <= 0)
                 || (!m_aUnits[m_iReadTail])
                 || (m_aUnits[m_iReadTail]->status() != CUnit::GOOD))
         {
            endpos = (m_iReadTail == 0 ? m_iSize - 1 : m_iReadTail - 1);
         }

         if ((NULL != m_aUnits[endpos]) && (NULL != m_aUnits[startpos]))
         {
            uint64_t startstamp = getPktTsbPdTime(m_aUnits[startpos]->ref_packet().getMsgTimeStamp());
            uint64_t endstamp = getPktTsbPdTime(m_aUnits[endpos]->ref_packet().getMsgTimeStamp());
            /* 
            * There are sampling conditions where spantime is < 0 (big unsigned value).
            * It has been observed after changing the SRT latency from 450 to 200 on the sender.
            *
            * Possible packet order corruption when dropping packet, 
            * cause by bad thread protection when adding packet in queue
            * was later discovered and fixed. Security below kept. 
            *
            * DateTime                 RecvRate LostRate DropRate AvailBw     RTT   RecvBufs PdDelay
            * 2014-12-08T15:04:25-0500     4712      110        0   96509  33.710        393     450
            * 2014-12-08T15:04:35-0500     4512       95        0  107771  33.493 1496542976     200
            * 2014-12-08T15:04:40-0500     4213      106        3  107352  53.657    9499425     200
            * 2014-12-08T15:04:45-0500     4575      104        0  102194  53.614      59666     200
            * 2014-12-08T15:04:50-0500     4475      124        0  100543  53.526        505     200
            */
            if (endstamp > startstamp)
                timespan = (int)((endstamp - startstamp) / 1000);
         }
         /* 
         * Timespan can be less then 1000 us (1 ms) if few packets. 
         * Also, if there is only one pkt in buffer, the time difference will be 0.
         * Therefore, always add 1 ms if not empty.
         */
         if (0 < m_iAckedPktsCount)
            timespan += 1;
      }
   }
   HLOGF(dlog.Debug, "getRcvDataSize: %6dp %6dB span=%6dms\n", m_iAckedPktsCount, m_iAckedBytesCount, timespan);
   bytes = m_iAckedBytesCount;
   return m_iAckedPktsCount;
}

int CRcvBuffer::getRcvAvgPayloadSize() const
{
   return m_iAvgPayloadSz;
}

void CRcvBuffer::dropMsg(int32_t msgno, bool using_rexmit_flag)
{
   for (int i = m_iReadHead, n = shift(m_iReadTail, m_iPastTailDelta); i != n; i = shift(i, 1))
      if ((m_aUnits[i] != NULL)
              && (m_aUnits[i]->ref_packet().getMsgSeq(using_rexmit_flag) == msgno))
         m_aUnits[i]->setDropped();
}

uint64_t CRcvBuffer::getTsbPdTimeBase(uint32_t timestamp)
{
   /* 
   * Packet timestamps wrap around every 01h11m35s (32-bit in usec)
   * When added to the peer start time (base time), 
   * wrapped around timestamps don't provide a valid local packet delevery time.
   *
   * A wrap check period starts 30 seconds before the wrap point.
   * In this period, timestamps smaller than 30 seconds are considered to have wrapped around (then adjusted).
   * The wrap check period ends 30 seconds after the wrap point, afterwhich time base has been adjusted.
   */ 
   uint64_t carryover = 0;

   // This function should generally return the timebase for the given timestamp.
   // It's assumed that the timestamp, for which this function is being called,
   // is received as monotonic clock. This function then traces the changes in the
   // timestamps passed as argument and catches the moment when the 64-bit timebase
   // should be increased by a "segment length" (MAX_TIMESTAMP+1).

   // The checks will be provided for the following split:
   // [INITIAL30][FOLLOWING30]....[LAST30] <-- == CPacket::MAX_TIMESTAMP
   //
   // The following actions should be taken:
   // 1. Check if this is [LAST30]. If so, ENTER TSBPD-wrap-check state
   // 2. Then, it should turn into [INITIAL30] at some point. If so, use carryover MAX+1.
   // 3. Then it should switch to [FOLLOWING30]. If this is detected,
   //    - EXIT TSBPD-wrap-check state
   //    - save the carryover as the current time base.

   if (m_bTsbPdWrapCheck) 
   {
       // Wrap check period.

       if (timestamp < TSBPD_WRAP_PERIOD)
       {
           carryover = uint64_t(CPacket::MAX_TIMESTAMP) + 1;
       }
       // 
       else if ((timestamp >= TSBPD_WRAP_PERIOD)
               &&  (timestamp <= (TSBPD_WRAP_PERIOD * 2)))
       {
           /* Exiting wrap check period (if for packet delivery head) */
           m_bTsbPdWrapCheck = false;
           m_ullTsbPdTimeCarryover += uint64_t(CPacket::MAX_TIMESTAMP) + 1;
           tslog.Debug("tsppd wrap period ends");
       }
   }
   // Check if timestamp is in the last 30 seconds before reaching the MAX_TIMESTAMP.
   else if (timestamp > (CPacket::MAX_TIMESTAMP - TSBPD_WRAP_PERIOD))
   {
      /* Approching wrap around point, start wrap check period (if for packet delivery head) */
      m_bTsbPdWrapCheck = true;
      tslog.Debug("tsppd wrap period begins");
   }
   return(m_ullTsbPdTimeBase + m_ullTsbPdTimeCarryover + carryover);
}

uint64_t CRcvBuffer::getPktTsbPdTime(uint32_t timestamp)
{
   return(getTsbPdTimeBase(timestamp) + m_uTsbPdDelay + timestamp + m_DriftTracer.drift());
}

int CRcvBuffer::setRcvTsbPdMode(uint64_t timebase, uint32_t delay)
{
    m_bTsbPdMode = true;
    m_bTsbPdWrapCheck = false;

    // Timebase passed here comes is calculated as:
    // >>> CTimer::getTime() - ctrlpkt->m_iTimeStamp
    // where ctrlpkt is the packet with SRT_CMD_HSREQ message.
    //
    // This function is called in the HSREQ reception handler only.
    m_ullTsbPdTimeBase = timebase;
    // XXX Seems like this may not work correctly.
    // At least this solution this way won't work with application-supplied
    // timestamps. For that case the timestamps should be taken exclusively
    // from the data packets because in case of application-supplied timestamps
    // they come from completely different server and undergo different rules
    // of network latency and drift.
    m_uTsbPdDelay = delay;
    return 0;
}

#ifdef SRT_DEBUG_TSBPD_DRIFT
void CRcvBuffer::printDriftHistogram(int64_t iDrift)
{
     /*
      * Build histogram of drift values
      * First line  (ms): <=-10.0 -9.0 ... -1.0 - 0.0 + 1.0 ... 9.0 >=10.0
      * Second line (ms):         -0.9 ... -0.1 - 0.0 + 0.1 ... 0.9
      *  0    0    0    0    0    0    0    0    0    0 -    0 +    0    0    0    1    0    0    0    0    0    0
      *       0    0    0    0    0    0    0    0    0 -    0 +    0    0    0    0    0    0    0    0    0
      */
    iDrift /= 100;  // uSec to 100 uSec (0.1ms)
    if (-10 < iDrift && iDrift < 10)
    {
        /* Fill 100us histogram -900 .. 900 us 100 us increments */
        m_TsbPdDriftHisto100us[10 + iDrift]++;
    }
    else
    {
        /* Fill 1ms histogram <=-10.0, -9.0 .. 9.0, >=10.0 ms in 1 ms increments */
        iDrift /= 10;   // 100uSec to 1ms
        if (-10 < iDrift && iDrift < 10) m_TsbPdDriftHisto1ms[10 + iDrift]++;
        else if (iDrift <= -10)          m_TsbPdDriftHisto1ms[0]++;
        else                             m_TsbPdDriftHisto1ms[20]++;
    }

    if ((m_iTsbPdDriftNbSamples % TSBPD_DRIFT_PRT_SAMPLES) == 0)
    {
        int *histo = m_TsbPdDriftHisto1ms;

        fprintf(stderr, "%4d %4d %4d %4d %4d %4d %4d %4d %4d %4d - %4d + ",
                histo[0],histo[1],histo[2],histo[3],histo[4],
                histo[5],histo[6],histo[7],histo[8],histo[9],histo[10]);
        fprintf(stderr, "%4d %4d %4d %4d %4d %4d %4d %4d %4d %4d\n",
                histo[11],histo[12],histo[13],histo[14],histo[15],
                histo[16],histo[17],histo[18],histo[19],histo[20]);

        histo = m_TsbPdDriftHisto100us;
        fprintf(stderr, "     %4d %4d %4d %4d %4d %4d %4d %4d %4d - %4d + ",
                histo[1],histo[2],histo[3],histo[4],histo[5],
                histo[6],histo[7],histo[8],histo[9],histo[10]);
        fprintf(stderr, "%4d %4d %4d %4d %4d %4d %4d %4d %4d\n",
                histo[11],histo[12],histo[13],histo[14],histo[15],
                histo[16],histo[17],histo[18],histo[19]);
    }
}

void CRcvBuffer::printDriftOffset(int tsbPdOffset, int tsbPdDriftAvg)
{
    char szTime[32] = {};
    uint64_t now = CTimer::getTime();
    time_t tnow = (time_t)(now/1000000);
    strftime(szTime, sizeof(szTime), "%H:%M:%S", localtime(&tnow));
    fprintf(stderr, "%s.%03d: tsbpd offset=%d drift=%d usec\n", 
            szTime, (int)((now%1000000)/1000), tsbPdOffset, tsbPdDriftAvg);
    memset(m_TsbPdDriftHisto100us, 0, sizeof(m_TsbPdDriftHisto100us));
    memset(m_TsbPdDriftHisto1ms, 0, sizeof(m_TsbPdDriftHisto1ms));
}
#endif /* SRT_DEBUG_TSBPD_DRIFT */

void CRcvBuffer::addRcvTsbPdDriftSample(uint32_t timestamp, pthread_mutex_t& mutex_to_lock)
{
    if (!m_bTsbPdMode) // Not checked unless in TSBPD mode
        return;
    /*
     * TsbPD time drift correction
     * TsbPD time slowly drift over long period depleting decoder buffer or raising latency
     * Re-evaluate the time adjustment value using a receiver control packet (ACK-ACK).
     * ACK-ACK timestamp is RTT/2 ago (in sender's time base)
     * Data packet have origin time stamp which is older when retransmitted so not suitable for this.
     *
     * Every TSBPD_DRIFT_MAX_SAMPLES packets, the average drift is calculated
     * if -TSBPD_DRIFT_MAX_VALUE < avgTsbPdDrift < TSBPD_DRIFT_MAX_VALUE uSec, pass drift value to RcvBuffer to adjust delevery time.
     * if outside this range, adjust this->TsbPdTimeOffset and RcvBuffer->TsbPdTimeBase by +-TSBPD_DRIFT_MAX_VALUE uSec
     * to maintain TsbPdDrift values in reasonable range (-5ms .. +5ms).
     */

    // Note important thing: this function is being called _EXCLUSIVELY_ in the handler
    // of UMSG_ACKACK command reception. This means that the timestamp used here comes
    // from the CONTROL domain, not DATA domain (timestamps from DATA domain may be
    // either schedule time or a time supplied by the application).

    int64_t iDrift = CTimer::getTime() - (getTsbPdTimeBase(timestamp) + timestamp);

    CGuard::enterCS(mutex_to_lock);

    bool updated = m_DriftTracer.update(iDrift);

#ifdef SRT_DEBUG_TSBPD_DRIFT
    printDriftHistogram(iDrift);
#endif /* SRT_DEBUG_TSBPD_DRIFT */

    if ( updated )
    {
#ifdef SRT_DEBUG_TSBPD_DRIFT
        printDriftOffset(m_DriftTracer.overdrift(), m_DriftTracer.drift());
#endif /* SRT_DEBUG_TSBPD_DRIFT */

        m_ullTsbPdTimeCarryover += m_DriftTracer.overdrift();
    }

    CGuard::leaveCS(mutex_to_lock);
}

int CRcvBuffer::readMsg(char* data, int len)
{
    SRT_MSGCTRL dummy = srt_msgctrl_default;
    return readMsg(data, len, Ref(dummy));
}


int CRcvBuffer::readMsg(char* data, int len, ref_t<SRT_MSGCTRL> r_msgctl)
{
    SRT_MSGCTRL& msgctl = *r_msgctl;
    int p, q;
    bool passack;
    bool empty = true;
    uint64_t& rplaytime = msgctl.srctime;

    if (m_bTsbPdMode)
    {
        passack = false;
        int seq = 0;

        if (getRcvReadyMsg(Ref(rplaytime), Ref(seq)))
        {
            empty = false;

            // In TSBPD mode you always read one message
            // at a time and a message always fits in one UDP packet,
            // so in one "unit".
            p = q = m_iReadHead;

#ifdef SRT_DEBUG_TSBPD_OUTJITTER
            uint64_t now = CTimer::getTime();
            if ((now - rplaytime)/10 < 10)
                m_ulPdHisto[0][(now - rplaytime)/10]++;
            else if ((now - rplaytime)/100 < 10)
                m_ulPdHisto[1][(now - rplaytime)/100]++;
            else if ((now - rplaytime)/1000 < 10)
                m_ulPdHisto[2][(now - rplaytime)/1000]++;
            else
                m_ulPdHisto[3][1]++;
#endif   /* SRT_DEBUG_TSBPD_OUTJITTER */
        }
    }
    else
    {
        rplaytime = 0;
        if (scanMsg(Ref(p), Ref(q), Ref(passack)))
            empty = false;

    }

    if (empty)
        return 0;

    // This should happen just once. By 'empty' condition
    // we have a guarantee that m_aUnits[p] exists and is valid.
    CPacket& pkt1 = m_aUnits[p]->ref_packet();

    // This returns the sequence number and message number to
    // the API caller.
    msgctl.pktseq = pkt1.getSeqNo();
    msgctl.msgno = pkt1.getMsgSeq();

    int rs = len;
    int past_q = shift(q, 1);
    while (p != past_q)
    {
        int unitsize = m_aUnits[p]->ref_packet().getLength();
        if ((rs >= 0) && (unitsize > rs))
            unitsize = rs;

        if (unitsize > 0)
        {
            memcpy(data, m_aUnits[p]->ref_packet().m_pcData, unitsize);
            data += unitsize;
            rs -= unitsize;
            /* we removed bytes form receive buffer */
            countBytes(-1, -unitsize, true);


#if ENABLE_HEAVY_LOGGING
            {
                static uint64_t prev_now;
                static uint64_t prev_srctime;

                int32_t seq = m_aUnits[p]->ref_packet().m_iSeqNo;

                uint64_t nowtime = CTimer::getTime();
                //CTimer::rdtsc(nowtime);
                uint64_t srctime = getPktTsbPdTime(m_aUnits[p]->ref_packet().getMsgTimeStamp());

                int64_t timediff = nowtime - srctime;
                int64_t nowdiff = prev_now ? (nowtime - prev_now) : 0;
                uint64_t srctimediff = prev_srctime ? (srctime - prev_srctime) : 0;

                HLOGC(dlog.Debug, log << CONID() << "readMsg: DELIVERED seq=" << seq << " T=" << logging::FormatTime(srctime) << " in " << (timediff/1000.0) << "ms - "
                    "TIME-PREVIOUS: PKT: " << (srctimediff/1000.0) << " LOCAL: " << (nowdiff/1000.0));

                prev_now = nowtime;
                prev_srctime = srctime;
            }
#endif
        }

        // Note special case for live mode (one packet per message and TSBPD=on):
        //  - p == q (that is, this loop passes only once)
        //  - no passack (the unit is always removed from the buffer)
        if (!passack)
        {
            freeUnitAt(p);
        }
        else
            m_aUnits[p]->setExtracted();

        if (++ p == m_iSize)
            p = 0;
    }

    if (!passack)
        m_iReadHead = shift(q, 1);

    return len - rs;
}


bool CRcvBuffer::scanMsg(ref_t<int> r_p, ref_t<int> r_q, ref_t<bool> passack)
{
    int& p = *r_p;
    int& q = *r_q;

    // empty buffer
    if ((m_iReadHead == m_iReadTail) && (m_iPastTailDelta <= 0))
    {
        HLOGC(mglog.Debug, log << "scanMsg: empty buffer");
        return false;
    }

    int rmpkts = 0;
    int rmbytes = 0;

    //skip all bad msgs at the beginning
    // This loop rolls until the "buffer is empty" (head == tail),
    // in particular, there's no units accessible for the reader.
    while (m_iReadHead != m_iReadTail)
    {
        // Roll up to the first valid unit
        // This skips all sequences for which the packets were
        // not received (lost, provided that if m_iReadTail %> m_iReadHead,
        // some packets were received in between).
        //
        // NOTE: a possibility that there exists any "hole" in the range
        // between HEAD and TAIL is only when the packet has been dismissed
        // intentionally due to DROPSEQ requirement sent by the peer.
        // (not TLPKTDROP because this works only with TSBPD=on, in which
        // case this function isn't used to extract data from the buffer).
        // Normally all packets between m_iReadHead and m_iReadTail should
        // be available.
        if (!m_aUnits[m_iReadHead])
        {
            if (++ m_iReadHead == m_iSize)
                m_iReadHead = 0;
            continue;
        }

        // Note: PB_FIRST | PB_LAST == PB_SOLO.
        // testing if boundary() & PB_FIRST tests if the msg is first OR solo.
        if ( m_aUnits[m_iReadHead]->status() == CUnit::GOOD
                && m_aUnits[m_iReadHead]->ref_packet().getMsgBoundary() & PB_FIRST )
        {
            // Ok, the situation is:
            //
            // |0|0|F|N|N|E|
            //      ^
            //       \              .
            //     m_iReadHead

            bool good = true;

            // look ahead for the whole message

            // We expect to see either of:
            // [PB_FIRST] [PB_SUBSEQUENT] [PB_SUBSEQUENT] [PB_LAST]
            // [PB_SOLO]
            // but not:
            // [PB_FIRST] NULL ...
            // [PB_FIRST] FREE/EXTRACTED/DROPPED...
            // If the message didn't look as expected, interrupt this.

            // the [PB_FIRST] is here locked, then this loop looks for
            // the end of message, including checking THIS message if
            // it's [PB_LAST] simultaneously (that is, it's [PB_SOLO]).

            // This begins with a message starting at m_iReadHead
            // up to m_iReadTail OR until the PB_LAST message is found.
            // If any of the units on this way isn't good, this OUTER loop
            // will be interrupted.
            for (int i = m_iReadHead; i != m_iReadTail;)
            {
                // (This condition is always false if i == m_iReadHead)
                if (!m_aUnits[i] || m_aUnits[i]->status() != CUnit::GOOD)
                {
                    // This means: break level=2
                    // (exit the loop: while (m_iReadHead != m_iReadTail))
                    good = false;
                    break;

                    // This is possible only in such a case:
                    // |0|0|F|N|0|E|
                    //      ^   ^
                    //       \  \=i
                    //     m_iReadHead
                    // Meaning: "can't extract the whole message. goto [OUT_CHECK]"
                }

                // Likewise, boundary() & PB_LAST will be satisfied for last OR solo.
                if ( m_aUnits[i]->ref_packet().getMsgBoundary() & PB_LAST )
                {
                    // So we are at:
                    // |0|0|F|N|N|E|
                    //      ^     ^
                    //       \    \=i
                    //     m_iReadHead
                    // Meaning: "reached the end. goto [END_CHECK]"
                    break;
                }

                // HERE IF: the unit at [i] is good, and is NOT PB_LAST
                // (either PB_FIRST or PB_SUBSEQUENT)

                // This is i++, for circular number up to m_iSize
                if (++ i == m_iSize)
                    i = 0;
            }

            if (good)
                break;
        }

        // [END_CHECK]

        // This actually deletes all units in the range
        // between m_iReadHead and m_iReadTail. This is done only
        // in case when [END_CHECK] was reached, which is done only
        // in case when the unit at m_iReadHead is good and marks the
        // beginning of the message.
        rmpkts++;
        rmbytes += freeUnitAt(m_iReadHead);

        // ++% m_iReadHead
        if (++ m_iReadHead == m_iSize)
            m_iReadHead = 0;
    }

    // ---> [OUT_CHECK]
    //
    // Possible situations:
    //
    // - m_iReadHead == m_iReadTail (acked range empty)
    // - m_iReadHead <% m_iReadTail, but there's no extractable full message pointed by m_iReadHead

    /* we removed bytes form receive buffer */
    countBytes(-rmpkts, -rmbytes, true);

    // Not sure if this is correct, but this above 'while' loop exits
    // under the following conditions only:
    // - m_iReadHead == m_iReadTail (that makes passack = true)
    // - found at least GOOD unit with PB_FIRST and not all messages up to PB_LAST are good,
    //   in which case it returns with m_iReadHead <% m_iReadTail (earlier)
    // Also all units that lied before m_iReadHead are removed.

    p = -1;                  // message head
    q = m_iReadHead;         // message tail
    *passack = m_iReadHead == m_iReadTail;
    bool found = false;

    // looking for the first message
    //>>m_aUnits[size + m_iPastTailDelta] is not valid 

    // XXX Would be nice to make some very thorough refactoring here.

    // This rolls by q variable from m_iReadHead up to m_iReadTail,
    // actually from the first message up to the one with PB_LAST
    // or PB_SOLO boundary.

    // The 'i' variable used in this loop is just a stub and it's
    // even hard to define the unit here. It is "shift towards
    // m_iReadHead", so the upper value is m_iPastTailDelta + size.
    // m_iPastTailDelta is itself relative to m_iReadTail, so
    // the upper value is m_iPastTailDelta + difference between
    // m_iReadTail and m_iReadHead, so that this value is relative
    // to m_iReadHead.
    //
    // The 'i' value isn't used anywhere, although the 'q' value rolls
    // in this loop in sync with 'i', with the difference that 'q' is
    // rolled back, and 'i' is just incremented normally.
    //
    // This makes that this loop rolls in the range by 'q' from
    // m_iReadHead to m_iReadHead + UPPER,
    // where UPPER = m_iReadTail -% m_iReadHead + m_iPastTailDelta
    // This embraces the range from the current reading head up to
    // the last packet ever received.
    //
    // 'passack' is set to true when the 'q' has passed through
    // the border of m_iReadTail and fallen into the range
    // of unacknowledged packets.

    for (int i = 0, n = m_iPastTailDelta + getRcvDataSize(); i < n; ++ i)
    {
        if (m_aUnits[q] && m_aUnits[q]->status() == CUnit::GOOD)
        {
            // Equivalent pseudocode:
            // PacketBoundary bound = m_aUnits[q]->ref_packet().getMsgBoundary();
            // if ( IsSet(bound, PB_FIRST) )
            //     p = q;
            // if ( IsSet(bound, PB_LAST) && p != -1 ) 
            //     found = true;
            //
            // Not implemented this way because it uselessly check p for -1
            // also after setting it explicitly.

            switch (m_aUnits[q]->ref_packet().getMsgBoundary())
            {
            case PB_SOLO: // 11
                p = q;
                found = true;
                break;

            case PB_FIRST: // 10
                p = q;
                break;

            case PB_LAST: // 01
                if (p != -1)
                    found = true;
                break;

            case PB_SUBSEQUENT:
                ; // do nothing (caught first, rolling for last)
            }
        }
        else
        {
            // a hole in this message, not valid, restart search
            p = -1;
        }

        // 'found' is set when the current iteration hit a message with PB_LAST
        // (including PB_SOLO since the very first message).
        if (found)
        {
            // the msg has to be ack'ed or it is allowed to read out of order, and was not read before
            if (!*passack || !m_aUnits[q]->ref_packet().getMsgOrderFlag())
            {
                HLOGC(mglog.Debug, log << "scanMsg: found next-to-broken message, delivering OUT OF ORDER.");
                break;
            }

            found = false;
        }

        if (++ q == m_iSize)
            q = 0;

        if (q == m_iReadTail)
            *passack = true;
    }

    // no msg found
    if (!found)
    {
        // NOTE:
        // This situation may only happen if:
        // - Found a packet with PB_FIRST, so p = q at the moment when it was found
        // - Possibly found following components of that message up to shifted q
        // - Found no terminal packet (PB_LAST) for that message.

        // if the message is larger than the receiver buffer, return part of the message
        if ((p != -1) && (shift(q, 1) == p))
        {
            HLOGC(mglog.Debug, log << "scanMsg: BUFFER FULL and message is INCOMPLETE. Returning PARTIAL MESSAGE.");
            found = true;
        }
        else
        {
            HLOGC(mglog.Debug, log << "scanMsg: PARTIAL or NO MESSAGE found: p=" << p << " q=" << q);
        }
    }
    else
    {
        HLOGC(mglog.Debug, log << "scanMsg: extracted message p=" << p << " q=" << q << " (" << ((q-p+m_iSize+1)%m_iSize) << " packets)");
    }

    return found;
}
