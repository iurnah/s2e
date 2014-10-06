/* 
 * DataStructureMonitor.h
 *
 * This is the Client plugin for the experiment, it response for all the
 * argument retrive and back tracking algorithms.
 *
 * Author:	Rui Han
 * Date:	29/09/2014
 */
#ifndef __S2E_PLUGINS_DATASTRUCTUREMONITOR_H__
#define __S2E_PLUGINS_DATASTRUCTUREMONITOR_H__

#include <iostream>
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include "DataStructureMonitor.h"
#include "LinuxInterruptMonitor.h"
#include "LinuxSyscallMonitor.h"

namespace s2e{
namespace plugins{

class DataStructureMonitor: public Plugin
{
	S2E_PLUGIN

	LinuxExecutionDetector *m_executionDetector;
	LinuxSyscallMonitor* m_LinuxSyscallMonitor;

	LinuxCodeSelector* m_LinuxCodeSelector;
	std::set<std::string> m_interceptedModules;
	sigc::connection m_onTranslateBlockEnd;

	bool m_onInt80Connected;
	bool m_onSysenterConnected;
	struct SSyscallInformation
	{
		int index;
		const char * name;
		int argcount;
		const char *arg0; 
		const char *arg1; 
		const char *arg2; 
		const char *arg3; 
		const char *arg4; 
		const char *arg5; 
		const char *arg6; 
	};

	struct X86State {
	   uint32_t eax;
	   uint32_t ebx;
	   uint32_t ecx;
	   uint32_t edx;
	   uint32_t esi;
	   uint32_t edi;
	   uint32_t ebp;
	   uint32_t esp;
	   uint32_t eip;
	   uint32_t cr2;
	}s;

	typedef struct SSyscallInformation SyscallInformation;	
	static SyscallInformation m_syscallInformation[];

public:		
	DataStructureMonitor(S2E *s2e): Plugin(s2e){}


	void initialize();

	void onModuleTransition(
				S2EExecutionState *state,
				const ModuleDescriptor *prevModule,
				const ModuleDescriptor *currentModule);

	void onTranslateBlockEnd(
					ExecutionSignal *signal,
					S2EExecutionState *state,
					TranslationBlock *tb,
					uint64_t pc, bool, uint64_t);

	void onInt80SyscallSignal(
					S2EExecutionState *state, uint64_t pc, 
					SyscallType type, uint32_t SyscallNr);

	void onSysenterSyscallSignal(
					S2EExecutionState *state, uint64_t pc, 
					SyscallType type, uint32_t SyscallNr);

	void slotTest(
			S2EExecutionState *state, uint64_t pc, 
			SyscallType type, uint32_t SyscallNr);

	static const SyscallInformation& getSyscallInformation(int syscallNr);

};


class DataStructureMonitorState: public PluginState
{
	//TODO Member virable to keep the per state info.
	DataStructureMonitor *m_plugin;

public:
	virtual DataStructureMonitorState* clone() const;
	static PluginState *factory(Plugin *p, S2EExecutionState *s);

	sigc::connection m_onInt80SyscallSignal;
	sigc::connection m_onSysenterSyscallSignal;

};


}//plugins
}//s2e
#endif
