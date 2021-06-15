
#ifndef BRO_PLUGIN_BRO_MMS
#define BRO_PLUGIN_BRO_MMS

#include <plugin/Plugin.h>

namespace plugin {
namespace Bro_MMS {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
