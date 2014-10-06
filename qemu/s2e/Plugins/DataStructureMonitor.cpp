/* 
 * DataStructureMonitor.cpp
 *
 * This is the Client plugin for the experiment, it response for all the
 * argument retrive and back tracking algorithms.
 *
 * Author:	Rui Han
 * Date:	29/09/2014
 */
include "DataStructureMonitor.h"
#include "LinuxSyscallMonitor.h"

#define SYSCALL_NUM_MAX 349

namespace s2e{
namespace plugins{
	
S2E_DEFINE_PLUGIN(DataStructureMonitor, "Retrive Data Structure plugin",
			   "DataStructureMonitor", "LinuxSyscallMonitor",
			   "LinuxCodeSelector", "LinuxExecutionDetector");

DataStructureMonitor::SyscallInformation DataStructureMonitor::m_syscallInformation[] = { 
#include "syscalls-table-3.2.57.h"

};
void DataStructureMonitor::initialize(){
	
	m_executionDetector = (LinuxExecutionDetector*)s2e()->getPlugin("LinuxExecutionDetector");
    assert(m_executionDetector);	

	m_LinuxSyscallMonitor = (LinuxSyscallMonitor*)s2e()->getPlugin("LinuxSyscallMonitor");
	assert(m_LinuxSyscallMonitor);

	m_LinuxCodeSelector = (LinuxCodeSelector*)s2e()->getPlugin("LinuxCodeSelector");
	assert(m_LinuxSyscallMonitor);
	
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
			s2e()->getWarningsStream() << "DataStructureMonitor: Module " << *it << " is inserted in m_interceptedModules!\n";
        }else {
            s2e()->getWarningsStream() << "DataStructureMonitor: Module " << *it << " is not configured\n";
            exit(-1);
        }
    }
	
	m_LinuxCodeSelector->onModuleTransitionSelector.connect(sigc::mem_fun(*this, 
							&DataStructureMonitor::onModuleTransition));

	s2e()->getDebugStream() << "DataStructureMonitor::initialize: " << '\n';
}

// This member function connect onTranslateBlockEnd from CorePlugins to make
// sure we intercept sysenter instruction inside the module we are interested,
// and ignore all other sysenter signals.
void DataStructureMonitor::onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule)
{
	//if current is in the interceptedModules, we intercept the syscalls
	if(m_interceptedModules.find(currentModule->Name) != m_interceptedModules.end()){
		if(!m_onTranslateBlockEnd.connected()){
			m_onTranslateBlockEnd = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
							sigc::mem_fun(*this, &DataStructureMonitor::onTranslateBlockEnd));
			
			//s2e()->getDebugStream() << "DataStructureMonitor::onModuleTransition: Connect onTranslateBlockEnd!" << "\n";
		}
	}else{//disable intercept the syscalls.
		m_onTranslateBlockEnd.disconnect();		
		//s2e()->getDebugStream() << "DataStructureMonitor::onModuleTransition: Disconnect m_onTranslateBlockEnd!" << "\n";
	}
}

void DataStructureMonitor::onTranslateBlockEnd(ExecutionSignal *signal,
                                          S2EExecutionState *state,
                                          TranslationBlock *tb,
                                          uint64_t pc, bool, uint64_t)
{
	//TODO: how to connect other plgState signals at this step.	
	//s2e()->getDebugStream() << "DataStructureMonitor::onTranslateBlockEnd: IN" << "\n";
	DECLARE_PLUGINSTATE(DataStructureMonitorState, state);
	// connect the onInt80syscallSignal and the onSysenterSyscallSignal when we enter the interested module
	if(m_LinuxSyscallMonitor){
#if 0
		if(!m_onInt80Connected){//make sure only connect once
			m_LinuxSyscallMonitor->getSyscallSignal(state, SYSCALL_INT).connect(
						sigc::mem_fun(*this, &DataStructureMonitor::onInt80SyscallSignal));

			s2e()->getDebugStream() << "DataStructureMonitor::onTranslateBlockEnd: onInt80SyscallSignal is connected!" << "\n";

			m_onInt80Connected = true;
		}		
#endif
		if(!plgState->m_onInt80SyscallSignal.connected()){
			plgState->m_onInt80SyscallSignal = m_LinuxSyscallMonitor->getSyscallSignal(state, SYSCALL_INT).connect(
						sigc::mem_fun(*this, &DataStructureMonitor::onInt80SyscallSignal));

			s2e()->getDebugStream(state) << "DataStructureMonitor::onTranslateBlockEnd: onInt80SyscallSignal is connected!" << "\n";
		}

		if(!plgState->m_onSysenterSyscallSignal.connected()){
			plgState->m_onSysenterSyscallSignal = m_LinuxSyscallMonitor->getSyscallSignal(state, SYSCALL_SYSENTER).connect(
						sigc::mem_fun(*this, &DataStructureMonitor::onSysenterSyscallSignal));
 
			s2e()->getDebugStream(state) << "DataStructureMonitor::onTranslateBlockEnd: onSysenterSyscallSignal is connected!" << "\n";
		}
#if 0
		if(!m_onSysenterConnected){//make sure only connect once
			m_LinuxSyscallMonitor->getSyscallSignal(state, SYSCALL_SYSENTER).connect(
						sigc::mem_fun(*this, &DataStructureMonitor::onSysenterSyscallSignal));

			s2e()->getDebugStream() << "DataStructureMonitor::onTranslateBlockEnd: onSysenterSyscallSignal is connected!" << "\n";

			m_onSysenterConnected = true;
		}		
#endif
	}else{
		s2e()->getWarningsStream() << "LinuxIniterruptMonitor plugin is missing, "
											"Cannot monitor syscalls via int 0x80" << '\n';
	}

}

void DataStructureMonitor::onInt80SyscallSignal(
							S2EExecutionState *state, 
							uint64_t pc, 
							SyscallType type, 
							uint32_t SyscallNr)
{
	assert(SyscallNr >= 0 && SyscallNr <= SYSCALL_NUM_MAX);

	s2e()->getDebugStream(state) << "onInt80SyscallSignal " << SyscallNr << '\n';
	s2e()->getMemoryTypeStream(state) << "onInt80SyscallSignal " << SyscallNr << '\n';

	if(SyscallNr > SYSCALL_NUM_MAX){
		s2e()->getWarningsStream(state) << "DataStructureMonitor::onInt80SyscallSignal: Invalid Syscall number!" << '\n';
		s2e()->getMemoryTypeStream(state) << "DataStructureMonitor::onInt80SyscallSignal: Invalid Syscall number!" << '\n';
	}

	target_ulong cr3 = state->readCpuState(CPU_OFFSET(cr[3]), sizeof(target_ulong) * 8);

	int argc = getSyscallInformation(SyscallNr).argcount;
	s2e()->getMemoryTypeStream(state) << "PID=" << hexval(cr3) << ", PC=" << hexval(pc) << ", SYSCALLNO:" << SyscallNr << " = "  
			<< getSyscallInformation(SyscallNr).name << ", (argN=" << getSyscallInformation(SyscallNr).argcount << ") " << "\n";
	switch(argc){
		case 0: 
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " ();" << '\n';
				s2e()->getMemoryTypeStream(state) << "NONE" << '\n';
				break;
		case 1: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				s2e()->getMemoryTypeStream(state) << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n';

				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "]);" << '\n';
				break;
		case 2: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );

				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], "
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "]);" << '\n';
				break;
		case 3: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				
				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n'
											 << hexval(s.edx) << " = " << getSyscallInformation(SyscallNr).arg2 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "], "
						<< getSyscallInformation(SyscallNr).arg2 << "[" << hexval(s.edx) << "]);" << '\n';
				break;
		case 4: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				
				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n'
											 << hexval(s.edx) << " = " << getSyscallInformation(SyscallNr).arg2 << '\n'
											 << hexval(s.esi) << " = " << getSyscallInformation(SyscallNr).arg3 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << hexval(s.edx) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << hexval(s.esi) << "]);" << '\n';
				break;
		case 5: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );

				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n'
											 << hexval(s.edx) << " = " << getSyscallInformation(SyscallNr).arg2 << '\n'
											 << hexval(s.esi) << " = " << getSyscallInformation(SyscallNr).arg3 << '\n'
											 << hexval(s.edi) << " = " << getSyscallInformation(SyscallNr).arg4 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << hexval(s.edx) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << hexval(s.esi) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << hexval(s.edi) << "]);" << '\n';
				break;
		case 6: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(s.ebp), sizeof (uint32_t) );
				
				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n'
											 << hexval(s.edx) << " = " << getSyscallInformation(SyscallNr).arg2 << '\n'
											 << hexval(s.esi) << " = " << getSyscallInformation(SyscallNr).arg3 << '\n'
											 << hexval(s.edi) << " = " << getSyscallInformation(SyscallNr).arg4 << '\n'
											 << hexval(s.ebp) << " = " << getSyscallInformation(SyscallNr).arg5 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << hexval(s.edx) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << hexval(s.esi) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << hexval(s.edi) << "], "
						<< getSyscallInformation(SyscallNr).arg5 << "[" << hexval(s.ebp) << "]);" << '\n';
				break;
	}
}

const DataStructureMonitor::SyscallInformation& DataStructureMonitor::getSyscallInformation(int syscallNr)
{
	static SyscallInformation symbolic_syscall = { 0, "SYMBOLIC-CALL-NUMBER", 0, "", "", "", "", "", "", "" };
	assert(syscallNr >= -1 && syscallNr <= SYSCALL_NUM_MAX);

	if (syscallNr == -1)
	{
		return symbolic_syscall;
	}

	return m_syscallInformation[syscallNr];
}

void DataStructureMonitor::onSysenterSyscallSignal(
							S2EExecutionState *state, 
							uint64_t pc, 
							SyscallType type, 
							uint32_t SyscallNr)
{
	assert(SyscallNr >= 0 && SyscallNr <= SYSCALL_NUM_MAX);

	s2e()->getDebugStream(state) << "onSysenterSyscallSignal " << SyscallNr << '\n';
	s2e()->getMemoryTypeStream(state) << "onSysenterSyscallSignal " << SyscallNr << '\n';


	if(SyscallNr > SYSCALL_NUM_MAX){
		s2e()->getWarningsStream(state) << "DataStructureMonitor::onSysenterSyscallSignal: Invalid Syscall number!" << '\n';
		s2e()->getMemoryTypeStream(state) << "DataStructureMonitor::onSysenterSyscallSignal: Invalid Syscall number!" << '\n';
	}

	target_ulong cr3 = state->readCpuState(CPU_OFFSET(cr[3]), sizeof(target_ulong) * 8);

	int argc = getSyscallInformation(SyscallNr).argcount;
	s2e()->getMemoryTypeStream(state) << "PID=" << hexval(cr3) << ", PC=" << hexval(pc) << ", SYSCALLNO:" << SyscallNr << " = "  
			<< getSyscallInformation(SyscallNr).name << ", (argN=" << getSyscallInformation(SyscallNr).argcount << ") " << '\n';
	switch(argc){
		case 0: 
				s2e()->getMemoryTypeStream(state) << "NONE" << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " ();" << '\n';
				break;
		case 1: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				s2e()->getMemoryTypeStream(state) << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n';

				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "]);" << '\n';
				break;
		case 2: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );

				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], "
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "]);" << '\n';
				break;
		case 3: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				
				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n'
											 << hexval(s.edx) << " = " << getSyscallInformation(SyscallNr).arg2 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "], "
						<< getSyscallInformation(SyscallNr).arg2 << "[" << hexval(s.edx) << "]);" << '\n';
				break;
		case 4: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				
				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n'
											 << hexval(s.edx) << " = " << getSyscallInformation(SyscallNr).arg2 << '\n'
											 << hexval(s.esi) << " = " << getSyscallInformation(SyscallNr).arg3 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << hexval(s.edx) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << hexval(s.esi) << "]);" << '\n';
				break;
		case 5: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );

				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n'
											 << hexval(s.edx) << " = " << getSyscallInformation(SyscallNr).arg2 << '\n'
											 << hexval(s.esi) << " = " << getSyscallInformation(SyscallNr).arg3 << '\n'
											 << hexval(s.edi) << " = " << getSyscallInformation(SyscallNr).arg4 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << hexval(s.edx) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << hexval(s.esi) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << hexval(s.edi) << "]);" << '\n';
				break;
		case 6: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(s.ebp), sizeof (uint32_t) );
				
				s2e()->getMemoryTypeStream() << hexval(s.ebx) << " = " << getSyscallInformation(SyscallNr).arg0 << '\n'
											 << hexval(s.ecx) << " = " << getSyscallInformation(SyscallNr).arg1 << '\n'
											 << hexval(s.edx) << " = " << getSyscallInformation(SyscallNr).arg2 << '\n'
											 << hexval(s.esi) << " = " << getSyscallInformation(SyscallNr).arg3 << '\n'
											 << hexval(s.edi) << " = " << getSyscallInformation(SyscallNr).arg4 << '\n'
											 << hexval(s.ebp) << " = " << getSyscallInformation(SyscallNr).arg5 << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << hexval(s.ebx) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << hexval(s.ecx) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << hexval(s.edx) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << hexval(s.esi) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << hexval(s.edi) << "], "
						<< getSyscallInformation(SyscallNr).arg5 << "[" << hexval(s.ebp) << "]);" << '\n';
				break;
	}
}

DataStructureMonitorState* DataStructureMonitorState::clone() const
{
	DataStructureMonitorState* ret = new DataStructureMonitorState(*this);
	return ret;
}

PluginState *DataStructureMonitorState::factory(Plugin *p, S2EExecutionState *s)
{
	DataStructureMonitorState *ret = new DataStructureMonitorState();
	ret->m_plugin = static_cast<DataStructureMonitor*>(p);
	return ret;
}

} //plugin
} //s2e
