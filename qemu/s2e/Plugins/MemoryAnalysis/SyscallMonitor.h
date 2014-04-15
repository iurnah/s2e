#ifndef	_SYSCALL_MONITOR_H_
#define _SYSCALL_MONITOR_H_

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/MemoryAnalysis/InterruptMonitor.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {
	
class SyscallMonitor: public Plugin
{
	S2E_PLUGIN

public:
	static const int MAX_SYSCALL_NR = 44;
	enum ESyscallType {
						SYSCALL_INT,
						SYSCALL_SYSENTER,
						SYSCALL_SYSCALL };
	struct SSyscallInformation
	{
		int argumentCount;
		int flags;
		const char * name;
		int misc;
	};

	typedef enum ESyscallType SyscallType;
	typedef struct SSyscallInformation SyscallInformation;
	typedef sigc::signal<void, S2EExecutionState*, uint64_t> SyscallReturnSignal;
	typedef sigc::signal<void, S2EExecutionState*, uint64_t, SyscallType, 
						uint32_t, SyscallReturnSignal& > SyscallSignal;
	typedef std::map< uint32_t, std::vector< SyscallMonitor::SyscallReturnSignal >> 
					SyscallReturnSignalsMap;

	SyscallMonitor(S2E *s2e): Plugin(s2e) {}
	virtual ~SyscallMonitor();

	void initialize();
	void onTranslateBlockEnd(ExecutionSignal *signal,
                             S2EExecutionState *state,
                             TranslationBlock *tb,
                             uint64_t pc, bool, uint64_t);
	void onSysenter(S2EExecutionState* state, uint64_t pc);
	void onSysexit(S2EExecutionState* state, uint64_t pc);
	void onInt80(S2EExecutionState* state, uint64_t pc, 
					int int_num,InterruptMonitor::InterruptReturnSignal& signal);
	static const SyscallInformation& getSyscallInformation(int syscallNr);
	SyscallSignal& getSyscallSignal(S2EExecutionState* state, int syscallNr);
	SyscallSignal& getAllSyscallsSignal(S2EExecutionState* state);
protected:
	void emitSyscallSignal(S2EExecutionState* state, uint64_t pc, 
							SyscallType syscall_type, SyscallReturnSignal& signal);
private:
	static SyscallInformation m_syscallInformation[];
	bool m_initialized;
};

//Plugin State for per state plugin information.
class SyscallMonitorState: public PluginState
{
	SyscallMonitor::SyscallSignal m_allSyscallsSignal;
	std::map<int, SyscallMonitor::SyscallSignal> m_signals;
	SyscallMonitor::SyscallReturnSignalsMap m_returnSignals;
	SyscallMonitor* m_plugin;
public:
    SyscallMonitorState() {}
    ~SyscallMonitorState() {}

    static PluginState * factory(Plugin*, S2EExecutionState*);
	SyscallMonitorState * clone() const ;

	friend class SyscallMonitor;
};

}	//namespace plugins
}	//namespace s2e

#endif /* _SYSCALL_MONITOR_H_ */
