/* 
 * DataStructureMonitor.cpp
 *
 * This is the Client plugin for the experiment, it response for all the
 * argument retrive and back tracking algorithms.
 *
 * Author:	Rui Han
 * Date:	29/09/2014
 */
#include "DataStructureMonitor.h"
#include "LinuxSyscallMonitor.h"

#include <llvm/Support/TimeValue.h>

#define SYSCALL_NUM_MAX 349

namespace s2e{
namespace plugins{
	
S2E_DEFINE_PLUGIN(DataStructureMonitor, "Retrive Data Structure plugin",
			   "DataStructureMonitor", "LinuxSyscallMonitor", "LinuxMemoryTracer",
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
	assert(m_LinuxCodeSelector);

	m_LinuxMemoryTracer = (LinuxMemoryTracer*)s2e()->getPlugin("LinuxMemoryTracer");
	assert(m_LinuxMemoryTracer);

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
	DECLARE_PLUGINSTATE(DataStructureMonitorState, state);
	if(m_LinuxSyscallMonitor){
		if(!plgState->m_onInt80SyscallSignal.connected()){//connect syscall signal for the particular state.
			plgState->m_onInt80SyscallSignal = m_LinuxSyscallMonitor->getSyscallSignal(state, SYSCALL_INT).connect(
						sigc::mem_fun(*this, &DataStructureMonitor::onInt80SyscallSignal));

			s2e()->getDebugStream(state) << "DataStructureMonitor::onTranslateBlockEnd: onInt80SyscallSignal is connected!" << "\n";
		}

		if(!plgState->m_onSysenterSyscallSignal.connected()){
			plgState->m_onSysenterSyscallSignal = m_LinuxSyscallMonitor->getSyscallSignal(state, SYSCALL_SYSENTER).connect(
						sigc::mem_fun(*this, &DataStructureMonitor::onSysenterSyscallSignal));
 
			s2e()->getDebugStream(state) << "DataStructureMonitor::onTranslateBlockEnd: onSysenterSyscallSignal is connected!" << "\n";
		}
	}else{
		s2e()->getWarningsStream() << "LinuxSyscallMonitor is missing, "
											"Cannot monitor syscalls via int 0x80 and sysenter instruction" << '\n';
	}
}

/*
 * TODO: get the timestamp here.
 */
void DataStructureMonitor::onInt80SyscallSignal(
							S2EExecutionState *state, 
							uint64_t pc, 
							SyscallType type, 
							uint32_t SyscallNr)
{
	DECLARE_PLUGINSTATE(DataStructureMonitorState, state);

	assert(SyscallNr >= 0 && SyscallNr <= SYSCALL_NUM_MAX);

	s2e()->getDebugStream(state) << "onInt80SyscallSignal " << SyscallNr << '\n';
	//s2e()->getMemoryTypeStream(state) << "onInt80SyscallSignal " << SyscallNr << '\n';

	if(SyscallNr > SYSCALL_NUM_MAX){
		s2e()->getWarningsStream(state) << "DataStructureMonitor::onInt80SyscallSignal: Invalid Syscall number!" << '\n';
		s2e()->getMemoryTypeStream(state) << "DataStructureMonitor::onInt80SyscallSignal: Invalid Syscall number!" << '\n';
	}

	//target_ulong cr3 = state->readCpuState(CPU_OFFSET(cr[3]), sizeof(target_ulong) * 8);

	int argc = getSyscallInformation(SyscallNr).argcount;
	//s2e()->getMemoryTypeStream(state) << "PID=" << hexval(cr3) << ", PC=" << hexval(pc) << ", SYSCALLNO:" << SyscallNr << " = "  
	//		<< getSyscallInformation(SyscallNr).name << ", (argN=" << getSyscallInformation(SyscallNr).argcount << ") " << "\n";
#if 0
	uint64_t timestamp = llvm::sys::TimeValue::now().usec();
	s2e()->getMemoryTypeStream() << timestamp << " ";
#endif
	s2e()->getMemoryTypeStream() << "s:" << llvm::sys::TimeValue::now().seconds() 
								 << "m:" << llvm::sys::TimeValue::now().milliseconds() 
								 << "u:" << llvm::sys::TimeValue::now().microseconds() 
								 << "n:" << llvm::sys::TimeValue::now().nanoseconds() << " ";

	switch(argc){
		case 0: 
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " ();" << '\n';
				s2e()->getMemoryTypeStream(state) << "NONE" << '\n';
				break;
		case 1: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				argCounts += 1;
				plgState->argCounts += 1;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
							(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';

				//output the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
							(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and perstate information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
							(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

				m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);

				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
											<< plgState->pointerArgCounts - plgState->overwrittenCounts <<'\n';

				
				break;
		case 2: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );

				plgState->argCounts += 2;
				argCounts += 2;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))<< "], "
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';

				//output the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))<< "], "
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx))
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and the perstate information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))<< "], "
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);

						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);

				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

				break;
		case 3: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				
				argCounts += 3;
				plgState->argCounts += 3;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], "
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';

				//output the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], "
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) 
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], "
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx);

				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

				break;
		case 4: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				
				argCounts += 4;
				plgState->argCounts += 4;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';
				
				//output the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi))
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

			
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx);
					   	m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi);
				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

				break;
		case 5: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );

				argCounts += 5 ;
				plgState->argCounts += 5 ;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';
				
				//output the perState information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) 
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
			//output the overall statistics and the perState information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

			
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edi); 
				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

				break;
		case 6: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(s.ebp), sizeof (uint32_t) );
				
				argCounts += 6;
				plgState->argCounts += 6;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) << "], "
						<< getSyscallInformation(SyscallNr).arg5 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebp, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebp)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';
				
				//output the perstate information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) << "], "
						<< getSyscallInformation(SyscallNr).arg5 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebp, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebp)) 
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
			//output the overall statistics and the perstate information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) << "], "
						<< getSyscallInformation(SyscallNr).arg5 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebp, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebp)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

			
					   	m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edi);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebp, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebp);
				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

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

/*
 * TODO: get the timestamp here.
 */
void DataStructureMonitor::onSysenterSyscallSignal(
							S2EExecutionState *state, 
							uint64_t pc, 
							SyscallType type, 
							uint32_t SyscallNr)
{
	DECLARE_PLUGINSTATE(DataStructureMonitorState, state);

	assert(SyscallNr >= 0 && SyscallNr <= SYSCALL_NUM_MAX);

	s2e()->getDebugStream(state) << "onSysenterSyscallSignal " << SyscallNr << '\n';
	//s2e()->getMemoryTypeStream(state) << "onSysenterSyscallSignal " << SyscallNr << '\n';


	if(SyscallNr > SYSCALL_NUM_MAX){
		s2e()->getWarningsStream(state) << "DataStructureMonitor::onSysenterSyscallSignal: Invalid Syscall number!" << '\n';
		s2e()->getMemoryTypeStream(state) << "DataStructureMonitor::onSysenterSyscallSignal: Invalid Syscall number!" << '\n';
	}

	//target_ulong cr3 = state->readCpuState(CPU_OFFSET(cr[3]), sizeof(target_ulong) * 8);

	int argc = getSyscallInformation(SyscallNr).argcount;
	/*
	s2e()->getMemoryTypeStream(state) << "PID=" << hexval(cr3) << ", PC=" << hexval(pc) << ", SYSCALLNO:" << SyscallNr << " = "  
			<< getSyscallInformation(SyscallNr).name << ", (argN=" << getSyscallInformation(SyscallNr).argcount << ") " << '\n';
	*/
#if 0
	uint64_t timestamp = llvm::sys::TimeValue::now().usec();
	s2e()->getMemoryTypeStream() << timestamp << " ";
#endif
	s2e()->getMemoryTypeStream() << "s:" << llvm::sys::TimeValue::now().seconds() 
								 << "m:" << llvm::sys::TimeValue::now().milliseconds() 
								 << "u:" << llvm::sys::TimeValue::now().microseconds() 
								 << "n:" << llvm::sys::TimeValue::now().nanoseconds() << " ";
	switch(argc){
		case 0: 
				s2e()->getMemoryTypeStream(state) << "NONE" << '\n';
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " ();" << '\n';
				break;
		case 1: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				argCounts += 1;
				plgState->argCounts += 1;

#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
							(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';

				//output the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
							(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and perstate information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
							(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

				m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);

				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';


				break;
		case 2: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );

				argCounts += 2;
				plgState->argCounts += 2;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))<< "], "
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';
				//output the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))<< "], "
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx))
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and the perstate information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx))<< "], "
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);

						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);

				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

				break;
		case 3: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				
				argCounts += 3;
				plgState->argCounts += 3;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], "
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';

				//output the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], "
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) 
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], "
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx);
				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

				break;
		case 4: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				
				argCounts += 4;
				plgState->argCounts += 4;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';
				
				//output the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi))
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and the perstate information.
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

			
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx);
					   	m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi);
				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

				break;
		case 5: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );

				argCounts += 5;
				plgState->argCounts += 5;
#if 0
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edi))
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';
				
				//output the perState information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) 
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
			//output the overall statistics and the perState information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

			
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edi); 
				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

				break;
		case 6: state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );
				state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(s.ebp), sizeof (uint32_t) );
				
				argCounts += 6;
				plgState->argCounts += 6;
#if 0				
				//output the overall statistics
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) << "], "
						<< getSyscallInformation(SyscallNr).arg5 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebp, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebp)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << '\n';
				
				//output the perstate information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) << "], "
						<< getSyscallInformation(SyscallNr).arg5 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebp, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebp)) 
						<< "]); Statistics=" << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << '\n';
#endif
				//output the overall statistics and the perstate information
				s2e()->getMemoryTypeStream(state) << getSyscallInformation(SyscallNr).name << " (" 
						<< getSyscallInformation(SyscallNr).arg0 << "[" << 
					   	(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg1 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ecx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx)) << "], " 
						<< getSyscallInformation(SyscallNr).arg2 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edx, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edx)) << "], "
						<< getSyscallInformation(SyscallNr).arg3 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.esi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.esi)) << "], "
						<< getSyscallInformation(SyscallNr).arg4 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.edi, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.edi)) << "], "
						<< getSyscallInformation(SyscallNr).arg5 << "[" << 
						(m_LinuxMemoryTracer->checkOverWrittenAddressesById(
							state->getID(), s.ebp, pointerArgCounts, overwrittenCounts) ? 0xdeadbeef : hexval(s.ebp)) 
						<< "]); Statistics=" << argCounts << ", " << pointerArgCounts << ", " << overwrittenCounts << ", " 
						<< pointerArgCounts - overwrittenCounts << ", ";

			
					   	m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ecx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ecx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edx, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edx);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.esi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.esi);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.edi, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.edi);
						m_LinuxMemoryTracer->checkOverWrittenAddressesByState(
							state, s.ebp, plgState->pointerArgCounts, plgState->overwrittenCounts) ? 0xdeadbeef : hexval(s.ebp);
				s2e()->getMemoryTypeStream() << plgState->argCounts << ", " << plgState->pointerArgCounts << ", " << plgState->overwrittenCounts << ", " 
					<< plgState->pointerArgCounts - plgState->overwrittenCounts << '\n';

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
