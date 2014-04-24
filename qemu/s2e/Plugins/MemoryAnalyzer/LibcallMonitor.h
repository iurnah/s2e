#ifndef	_SYSCALL_MONITOR_H
#define _SYSCALL_MONITOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
//#include <s2e/Plugins/MemoryAnalysis/>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {
	
class SyscallMonitor: public Plugin
{
	S2E_PLUGIN

public:
	SyscallMonitor(S2E *s2e): Plugin(s2e) {	}
	sigc::signal<void, S2EExecutionState *, uint64_t> onXXX;
	
	void initialize();
	void MemberFunction(S2EExecutionState *state, uint64_t pc);

};

}	//namespace plugins
}	//namespace s2e

//Plugin State for per state plugin information.
class SyscallMonitorState: public PluginState
{

public:
    SyscallMonitorState() {}

    ~SyscallMonitorState() {}


    static PluginState * factory(Plugin*, S2EExecutionState*) {
        return new SyscallMonitorState();
    }

   SyscallMonitorState * clone() const {
        return new SyscallMonitorState(*this);
    }

    void increment() { ++m_count; }
    int get() { return m_count; }

};
#endif

