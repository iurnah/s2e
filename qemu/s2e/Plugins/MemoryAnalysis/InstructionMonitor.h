#ifndef	_SYSCALL_INSTRUCMONITOR_H
#define _SYSCALL_INSTRUCMONITOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {
	
class InstrucMonitor: public Plugin
{
	S2E_PLUGIN

public:
	InstrucMonitor(S2E *s2e): Plugin(s2e) {	}
	sigc::signal<void, S2EExecutionState *, uint64_t> onXXX;
	
	void initialize();
	void MemberFunction(S2EExecutionState *state, uint64_t pc);

};

}	//namespace plugins
}	//namespace s2e

//Plugin State for per state plugin information.
class InstrucMonitorState: public PluginState
{

public:
    InstrucMonitorState() {}

    ~InstrucMonitorState() {}


    static PluginState * factory(Plugin*, S2EExecutionState*) {
        return new InstrucMonitorState();
    }

   InstrucMonitorState * clone() const {
        return new InstrucMonitorState(*this);
    }

    void increment() { ++m_count; }
    int get() { return m_count; }

};
#endif

