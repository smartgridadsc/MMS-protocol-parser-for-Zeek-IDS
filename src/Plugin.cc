
#include "Plugin.h"
#include "MMS.h"

namespace plugin { namespace Bro_MMS { Plugin plugin; } }

using namespace plugin::Bro_MMS;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::analyzer::Component("MMS",
	             ::analyzer::MMS::MMS_Analyzer::InstantiateAnalyzer));

	plugin::Configuration config;
	config.name = "Bro::MMS";
	config.description = "IEC61850 MMS analyzer";
	config.version.major = 1;
	config.version.minor = 0;
	return config;
	}
