#ifndef INC__LOGSUPPORT_HPP
#define INC__LOGSUPPORT_HPP

#include "../srtcore/logging_api.h"

logging::LogLevel::type SrtParseLogLevel(std::string level);
std::set<logging::LogFA> SrtParseLogFA(std::string fa);

extern std::map<std::string, int> srt_level_names;


#endif
