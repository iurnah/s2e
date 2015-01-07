/*
 * SyscallMonitor.cpp
 *
 *  Created on: Dec 8, 2011
 *      Author: zaddach
 */

extern "C" {
#include "qemu-common.h"
}

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include "CorePlugin.h"
#include "LinuxSyscallMonitor.h"
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxSyscallMonitor, "Linux syscall monitoring plugin", 
				"LinuxSyscallMonitor", "LinuxExecutionDetector", 
				"LinuxCodeSelector", "LinuxInterruptMonitor"); 
#if 0
LinuxSyscallMonitor::SyscallInformation LinuxSyscallMonitor::m_syscallInformation[] = { 
#include "syscalls-table-3.2.57.h"

};
#endif

LinuxSyscallMonitor::LinuxSyscallMonitor(S2E* s2e) : Plugin(s2e) {
	// TODO Auto-generated constructor stub

}

LinuxSyscallMonitor::~LinuxSyscallMonitor() {
	// TODO Auto-generated destructor stub
}

void LinuxSyscallMonitor::initialize()
{
	m_executionDetector = (LinuxExecutionDetector*)s2e()->getPlugin("LinuxExecutionDetector");
    assert(m_executionDetector);
	m_LinuxCodeSelector = (LinuxCodeSelector*)s2e()->getPlugin("LinuxCodeSelector");	

	m_LinuxInterruptMonitor = (LinuxInterruptMonitor*)s2e()->getPlugin("LinuxInterruptMonitor");

	//Fetch the list of modules where forking should be enabled
    ConfigFile *cfg = s2e()->getConfig();
	bool ok = false;

    ConfigFile::string_list moduleList =
            cfg->getStringList(getConfigKey() + ".moduleIds", ConfigFile::string_list(), &ok);

    if (!ok || moduleList.empty()) {
        s2e()->getWarningsStream() << "You should specify a list of modules in " <<
                getConfigKey() + ".moduleIds\n";
    }

    foreach2(it, moduleList.begin(), moduleList.end()) {
        if (m_executionDetector->isModuleConfigured(*it)) {
            m_interceptedModules.insert(*it);
			s2e()->getWarningsStream() << "LinuxSyscallMonitor: Module " << *it << " is inserted in m_interceptedModules!\n";
        }else {
            s2e()->getWarningsStream() << "LinuxSyscallMonitor: " << "Module " << *it << " is not configured\n";
            exit(-1);
        }
    }
	
	//we use onModuleTransitionSelector from LinuxCodeSelector to enable signal
	//emition from the interested module.
	m_LinuxCodeSelector->onModuleTransitionSelector.connect(sigc::mem_fun(*this, 
							&LinuxSyscallMonitor::onModuleTransition));

}

// This member function connect onTranslateBlockEnd from CorePlugins to make
// sure we intercept sysenter instruction inside the module we are interested,
// and ignore all other sysenter signals.
void LinuxSyscallMonitor::onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule)
{
	//if current is in the interceptedModules, we intercept the syscalls
	if(m_interceptedModules.find(currentModule->Name) != m_interceptedModules.end()){
		if(!m_onTranslateBlockEnd.connected()){
			m_onTranslateBlockEnd = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
							sigc::mem_fun(*this, &LinuxSyscallMonitor::onTranslateBlockEnd));

			s2e()->getDebugStream() << "LinuxSyscallMonitor::onModuleTransition: Connect the onTranslateBlockEnd! " << "\n";
		}
	}else{//disable intercept the syscalls.
		m_onTranslateBlockEnd.disconnect();		
		s2e()->getDebugStream() << "LinuxSyscallMonitor::onModuleTransition: Disconnect the onTranslateBlockEnd! " << "\n";
	}
}

void LinuxSyscallMonitor::onTranslateBlockEnd(ExecutionSignal *signal,
                                          S2EExecutionState *state,
                                          TranslationBlock *tb,
                                          uint64_t pc, bool, uint64_t)
{
	// connect each different plgState signals at this step, so no matter in
	// which plgState, it will call the callback
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);
#if 0	
	// connect the Int80 interrupt signal for the current plgState when we 
	// enter the interested module
	if(!m_onInt80Connected){//make sure only connect once
		if(m_LinuxInterruptMonitor){
			m_LinuxInterruptMonitor->getInterruptSignal(state, 0x80).connect(
						sigc::mem_fun(*this, &LinuxSyscallMonitor::onInt80));
		}else{
			s2e()->getWarningsStream() << "LinuxIniterruptMonitor plugin is missing, "
											"Cannot monitor syscalls via int 0x80" << '\n';
		}
		m_onInt80Connected = true;
	}
#endif

	if(!plgState->m_InterruptSignal.connected()){
		plgState->m_InterruptSignal = m_LinuxInterruptMonitor->getInterruptSignal(
						state, 0x80).connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onInt80));
	}

	if (tb->s2e_tb_type == TB_SYSENTER)
	{
		signal->connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onSysenter));
	}
}

void LinuxSyscallMonitor::onInt80(S2EExecutionState* state, uint64_t pc, int interruptNum)
{
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);
	uint32_t eax = 0xFFFFFFFF;
	s2e()->getDebugStream(state) << "LinuxSyscallMonitor::onInt80 slot function!!" << '\n';

	if(state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax)))
	{
		std::map<int, SyscallSignal>::iterator itr = plgState->m_signals.find(SYSCALL_INT);
		if(itr != plgState->m_signals.end())
		{
			itr->second.emit(state, pc, SYSCALL_INT, eax);
		}else {
			s2e()->getDebugStream(state) << "LinuxSyscallMonitor::onInt80SyscallSignal, With Symbolic syscall number (EAX)!" << '\n';
			s2e()->getWarningsStream(state) << "LinuxSyscallMonitor::onInt80SyscallSignal, With Symbolic syscall number (EAX)!" << '\n';
			//s2e()->getMemoryTypeStream(state) << "LinuxSyscallMonitor::onInt80SyscallSignal, With Symbolic syscall number (EAX)!" << '\n';
		}
	}
}

void LinuxSyscallMonitor::onSysenter(S2EExecutionState* state, uint64_t pc)
{
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	target_ulong ebp = 0;
	target_ulong eip = 0;

	//On SYSENTER, the current stack pointer of the user mode code is stored in EBP, exactly the SYSENTER is
	//preceded by
	//xxxxxxxx: call 0xffffe400
	//ffffe400: 51 push %ecx
	//ffffe401: 52 push %edx
	//ffffe402: 55 push %ebp
	//ffffe403: 89 e5 mov %esp,%ebp
	//ffffe405: 0f 34 sysenter
	//(from linux-gate.so)
	//HAHA, the above information is correct, but I got fooled by the assumption that SYSEXIT directly
	//jumps to the return point - it does not, but jumps instead after the SYSCALL instruction in the
	//vsyscall page. So to summarize, there is only ONE SYSCALL instruction, which is located in the vsyscall
	//page at 0xffff4000, and SYSEXIT always returns to after this instruction.
	if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBP]), &ebp, sizeof(ebp)))
	{
		s2e()->getWarningsStream() << "SYSENTER has symbolic EBP value at 0x" << hexval(pc) << '\n';
	}

	if (!state->readMemoryConcrete(ebp + 12, &eip, sizeof(eip), S2EExecutionState::VirtualAddress))
	{
		s2e()->getWarningsStream() << "SYSENTER has symbolic EIP value at 0x" << hexval(pc) << '\n';
	}


	plgState->m_returnSignals[eip].push_back(SyscallReturnSignal());

	s2e()->getDebugStream(state) << "SYSENTER return address 0x" << hexval(eip) << '\n';
	
	
	s2e()->getDebugStream(state) << "LinuxSyscallMonitor::onSysenterSyscallSignal before signal emitted!!" << '\n';

	uint32_t eax = 0xFFFFFFFF;
#if 0
	if(!plgState->m_signals.empty()){
		SyscallSignal& signal = plgState->m_signals.back();

		signal.emit(state, pc, SYSCALL_SYSENTER, eax);
	}
#endif
	if(state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax)))
	{
		std::map<int, SyscallSignal>::iterator itr = plgState->m_signals.find(SYSCALL_SYSENTER);
		if(itr != plgState->m_signals.end())
		{
			itr->second.emit(state, pc, SYSCALL_SYSENTER, eax);
		}
		s2e()->getDebugStream(state) << "LinuxSyscallMonitor::onSysenterSyscallSignal after signal emitted!!" << '\n';
	}
	

}

LinuxSyscallMonitor::SyscallSignal& LinuxSyscallMonitor::getSyscallSignal(S2EExecutionState* state, SyscallType type)
{
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	assert(type >= SYSCALL_INT && type < SYSCALL_SYSCALL);

	return plgState->m_signals[type];
}

#if 0
//work with one connection.
LinuxSyscallMonitor::SyscallSignal& LinuxSyscallMonitor::getSyscallSignal(S2EExecutionState* state, SyscallType type)
{
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	//assert(syscallNr >= SYSCALL_INT && type < SYSCALL_SYSCALL);

	//we push all the signals to a vectors.
	plgState->m_signals.push_back(SyscallSignal());
	return plgState->m_signals.back();
}
#endif

LinuxSyscallMonitorState* LinuxSyscallMonitorState::clone() const
{
	LinuxSyscallMonitorState *ret = new LinuxSyscallMonitorState(*this);
    assert(ret->m_returnSignals.size() == m_returnSignals.size());
    return ret;
}

PluginState *LinuxSyscallMonitorState::factory(Plugin *p, S2EExecutionState *s)
{
	LinuxSyscallMonitorState *ret = new LinuxSyscallMonitorState();
    ret->m_plugin = static_cast<LinuxSyscallMonitor*>(p);
    return ret;
}

} //namespace plugins
} //namespace s2e

