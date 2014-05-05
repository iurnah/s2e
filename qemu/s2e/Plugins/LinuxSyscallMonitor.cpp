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
#include <s2e/Utils.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxSyscallMonitor, "Linux syscall monitoring plugin", "ModuleExecutionDetector",);  //add by sun for special module

static const int TP = 0x1;
static const int TD = 0x2;
static const int TF = 0x4;
static const int NF = 0x8;
static const int TN = 0x10;
static const int TI = 0x20;
static const int TS = 0x40;


LinuxSyscallMonitor::SyscallInformation LinuxSyscallMonitor::m_syscallInformation[] = {
#include "syscallent-simple.h"
};

LinuxSyscallMonitor::LinuxSyscallMonitor(S2E* s2e) : Plugin(s2e) {
	// TODO Auto-generated constructor stub

}

LinuxSyscallMonitor::~LinuxSyscallMonitor() {
	// TODO Auto-generated destructor stub
}

void LinuxSyscallMonitor::initialize()
{

	m_detector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin("ModuleExecutionDetector"));  // add by sun for special module
	s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onTranslateBlockEnd));
//	s2e()->getCorePlugin()->onTranslateJumpStart.connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onTranslateJumpStart));
	m_detector->onModuleLoad.connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onModuleLoad));     //add by sun for special module

	m_initialized = false;
	s2e()->getDebugStream() << "LinuxSyscallMonitor: Plugin initialized!!!" << '\n';
}

/* add by sun for specail module */
void LinuxSyscallMonitor::onModuleLoad( S2EExecutionState* state, const ModuleDescriptor &module)
{
	spe_pid = module.Pid;
}

void LinuxSyscallMonitor::onTranslateBlockEnd(ExecutionSignal *signal,
                                          S2EExecutionState *state,
                                          TranslationBlock *tb,
                                          uint64_t pc, bool, uint64_t)
{
	if (!m_initialized)
	{
		Plugin* intMonPlugin = s2e()->getPlugin("InterruptMonitor");
		if (intMonPlugin)
		{
			reinterpret_cast<InterruptMonitor *>(intMonPlugin)->getInterruptSignal(state, 0x80).connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onInt80));
		}
		else
		{
			s2e()->getWarningsStream() << "InterruptMonitor plugin missing. Cannot monitor syscalls via int 0x80" << '\n';
		}

		m_initialized = true;
	}

	if (tb->s2e_tb_type == TB_SYSENTER)
	{
		signal->connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onSysenter));
	}
	else if (tb->s2e_tb_type == TB_SYSEXIT)
	{
		signal->connect(sigc::mem_fun(*this, &LinuxSyscallMonitor::onSysexit));
	}

}

void LinuxSyscallMonitor::onSysenter(S2EExecutionState* state, uint64_t pc)
{
	//s2e()->getWarningsStream() << "onSysenter "<< "'\n";
	target_ulong ebp = 0;
	target_ulong eip = 0;

	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

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

	//s2e()->getWarningsStream() << m_returnSignals << '\n';

//	s2e()->getDebugStream() << "SYSENTER return address 0x" << std::hex << eip << std::endl;
	emitSyscallSignal(state, pc, SYSCALL_SYSENTER, plgState->m_returnSignals[eip].back());
}

void LinuxSyscallMonitor::onSysexit(S2EExecutionState* state, uint64_t pc)
{
	target_ulong esp = 0;
	target_ulong eip = 0;

	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &esp, sizeof(esp)))
	{
		s2e()->getWarningsStream() << "SYSEXIT has symbolic EBP at 0x" << hexval(pc) << '\n';
	}

	if (!state->readMemoryConcrete(esp + 12, &eip, sizeof(eip), S2EExecutionState::VirtualAddress))
	{
		s2e()->getWarningsStream() << "SYSEXIT has symbolic return address at 0x" << hexval(pc) << '\n';
	}

	SyscallReturnSignalsMap::iterator itr = plgState->m_returnSignals.find(eip);

	if (itr != plgState->m_returnSignals.end())
	{
		SyscallReturnSignal& sig = itr->second.back();
		sig.emit(state, pc);
		itr->second.pop_back();
	}


//	s2e()->getDebugStream() << "SYSEXIT at 0x" << std::hex << pc << " returning to 0x" << std::hex << eip << std::endl;
}

void LinuxSyscallMonitor::onInt80(S2EExecutionState* state, uint64_t pc, int int_num, InterruptMonitor::InterruptReturnSignal& signal)
{
	if (int_num == 0x80)
	{
		emitSyscallSignal(state, pc, SYSCALL_INT, signal);
	}
	else
	{
		s2e()->getDebugStream() << "LinuxSyscallMonitor received interrupt signal from InterruptMonitor that was not int 0x80" << '\n';
	}
}

const LinuxSyscallMonitor::SyscallInformation& LinuxSyscallMonitor::getSyscallInformation(int syscallNr) {
	static SyscallInformation symbolic_syscall = {0, 0, "symbolic syscall number", 0};

	assert(syscallNr >= -1 && syscallNr <= MAX_SYSCALL_NR);

	if (syscallNr == -1)
	{
		return symbolic_syscall;
	}

	return m_syscallInformation[syscallNr];
}

LinuxSyscallMonitor::SyscallSignal& LinuxSyscallMonitor::getAllSyscallsSignal(S2EExecutionState* state)
{
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	return plgState->m_allSyscallsSignal;
}

LinuxSyscallMonitor::SyscallSignal& LinuxSyscallMonitor::getSyscallSignal(S2EExecutionState* state, int syscallNr)
{
	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	assert(syscallNr >= 0 && syscallNr < MAX_SYSCALL_NR);

	return plgState->m_signals[syscallNr];
}

void LinuxSyscallMonitor::emitSyscallSignal(S2EExecutionState* state, uint64_t pc, SyscallType syscall_type, SyscallReturnSignal& signal)
{
	// add by sun for track configured modules
	//Only track configured modules
    //uint64_t caller = state->getTb()->pcOfLastInstr;
    //const ModuleDescriptor *mod = m_detector->getModule(state, caller);
    //if (!mod) {
    //    return;
    //}
	//add by sun track configured modules

	uint32_t eax = 0xFFFFFFFF;
	target_ulong cr3 = state->readCpuState(CPU_OFFSET(cr[3]), sizeof(target_ulong) * 8);
	//state->readCpuState(CPU_OFFSET(cr[3]), sizeof(target_ulong) * 8);

	DECLARE_PLUGINSTATE(LinuxSyscallMonitorState, state);

	if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax)))
	{
		s2e()->getWarningsStream() << "Syscall with symbolic syscall number (EAX)!" << '\n';
	}

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

	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EAX]), &(s.eax), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(s.ebp), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(s.esp), sizeof (uint32_t) );

	if (eax != 0xFFFFFFFF)
	{
		std::map<int, SyscallSignal>::iterator itr = plgState->m_signals.find(eax);

		if (itr != plgState->m_signals.end())
		{
			itr->second.emit(state, pc, syscall_type, eax, signal);
		}
	}

	plgState->m_allSyscallsSignal.emit(state, pc, syscall_type, eax, signal);
	
	s2e()->getDebugStream(state) << "0x" << hexval(pc)  << ": System call " << eax  << "/" <<
			getSyscallInformation(eax).name << " (" << syscall_type << ") in process " <<  hexval(cr3) << '\n';
	s2e()->getDebugStream (state) <<" eax:" << hexval(s.eax) << " ebx:" << hexval(s.ebx) << " ecx:" << hexval(s.ecx) << " edx:" 
			<< hexval(s.edx)<< " esi:" << hexval(s.esi) << " edi:" << hexval(s.edi) << " ebp:" << hexval(s.ebp) << " esp:" << hexval(s.esp) << "\n";
	
	//s2e()->getMessagesStream(state) << "20 "<< "'\n";
	//if (spe_pid && state->getPid() == spe_pid)
			
	//s2e()->getWarningsStream(state) << "0x" << hexval(pc)  << ": System call " << eax  << "/" <<
	//		getSyscallInformation(eax).name << " (" << syscall_type << ") in process " <<  hexval(cr3) << '\n';

    //s2e()->getMessagesStream(state) << "0x" << hexval(pc)  << ": System call 0x" << hexval(eax)  << "/" <<
	//							getSyscallInformation(eax).name << " (" << syscall_type << ") in process " <<  hexval(cr3) << '\n';
	//s2e()->getMessagesStream(state) << "21 "<< "'\n";
}


LinuxSyscallMonitorState* LinuxSyscallMonitorState::clone() const
{
	LinuxSyscallMonitorState *ret = new LinuxSyscallMonitorState(*this);
//    m_plugin->s2e()->getDebugStream() << "Forking FunctionMonitorState ret=" << std::hex << ret << std::endl;
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

