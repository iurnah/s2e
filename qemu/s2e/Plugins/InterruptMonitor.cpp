/*
 * InterruptMonitor.cpp
 *
 *  Created on: Dec 8, 2011
 *      Author: zaddach
 */

extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include <vector>
#include <map>

#include <s2e/S2E.h>
//#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/InterruptMonitor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

using std::vector;
using std::map;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InterruptMonitor, "software interrupt monitoring plugin", "InterruptMonitor", "ModuleExecutionDetector");

void InterruptMonitor::initialize()
{
	m_executionDetector = (ModuleExecutionDetector*)s2e()->getPlugin("ModuleExecutionDetector");
    assert(m_executionDetector);
	
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
			s2e()->getWarningsStream() << "InterruptMonitor: Module " << *it << " is inserted in m_interceptedModules!\n";
        }else {
            s2e()->getWarningsStream() << "InterruptMonitor: " << "Module " << *it << " is not configured\n";
            exit(-1);
        }
    }

    m_executionDetector->onModuleTransition.connect(sigc::mem_fun(*this, &InterruptMonitor::onModuleTransition));

	s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &InterruptMonitor::slotTranslateBlockEnd));
	s2e()->getCorePlugin()->onTranslateJumpStart.connect(sigc::mem_fun(*this, &InterruptMonitor::onTranslateJumpStart));
	s2e()->getDebugStream() << "InterruptMonitor: Plugin initialized!!!" << '\n';
}

InterruptMonitor::InterruptSignal& InterruptMonitor::getInterruptSignal(S2EExecutionState* state, int interrupt)
{
	DECLARE_PLUGINSTATE(InterruptMonitorState, state);

	assert (interrupt >= -1 && interrupt <= 0xff);

	return plgState->m_signals[interrupt];
}

void InterruptMonitor::slotTranslateBlockEnd(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc, bool, uint64_t)
{

	if (tb->s2e_tb_type == TB_INTERRUPT) //XXX: Currently not be able to detect TB_INTERRUPT
	{
		signal->connect(sigc::mem_fun(*this, &InterruptMonitor::onInterrupt));
	}
}

void InterruptMonitor::onTranslateJumpStart(ExecutionSignal *signal,
                                             S2EExecutionState *state,
                                             TranslationBlock * tb,
                                             uint64_t pc, int jump_type)
{
	if (jump_type == JT_IRET)
	{
		signal->connect(sigc::mem_fun(*this, &InterruptMonitor::onInterruptReturn));
		s2e()->getDebugStream() << "InterruptMonitor: onInterruptReturn connected!!!" << '\n';
	}
}

void InterruptMonitor::onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule)
{
#if 0
    if (!currentModule) {
        //state->disableForking();
		flag_isInterceptedModules = false;
		s2e()->getMemoryTypeStream(state) << "InterruptMonitor::set the flag to false when the current module if NULL" << '\n';
        return;
    }
	
	if(prevModule == NULL){
		s2e()->getMemoryTypeStream(state) << "InterruptMonitor::onModuleTransition: prevModule=NULL" << '\n';
	}else 
		s2e()->getMemoryTypeStream(state) << "InterruptMonitor::onModuleTransition: prevModule=" << 
			prevModule->Name << " currentModule=" << currentModule->Name << '\n';

    const std::string *id = m_executionDetector->getModuleId(*currentModule);
    if (m_interceptedModules.find(*id) != m_interceptedModules.end()) {
        //state->disableForking(); //in s2e-out-38, this never reached.
		flag_isInterceptedModules = true;
		s2e()->getMemoryTypeStream(state) << "InterruptMonitor::set the flag to true because of enter not intercept module" << '\n';
        return;
    }

	s2e()->getMemoryTypeStream(state) << "InterruptMonitor::set the flag to false because of enter the moduleId = " << *id << '\n';
//	flag_isInterceptedModules = false; //TODO: is there a fourth possible of transition? 
#endif
}

void InterruptMonitor::onInterruptReturn(S2EExecutionState* state, uint64_t pc)
{
	target_ulong esp = 0;
	target_ulong eip = 0;

	DECLARE_PLUGINSTATE(InterruptMonitorState, state);

	if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]), &esp, sizeof(esp)))
	{
		s2e()->getWarningsStream() << "IRET has symbolic ESP register at 0x" << hexval(pc) << '\n';
	}

	if (!state->readMemoryConcrete(esp, &eip, sizeof(eip), S2EExecutionState::VirtualAddress))
	{
		s2e()->getWarningsStream() << "IRET at 0x" << hexval(pc) << " has symbolic EIP value at memory address 0x" <<
				hexval(esp) << '\n';
	}


	ReturnSignalsMap::iterator itr = plgState->m_returnSignals.find(eip);

	if (itr != plgState->m_returnSignals.end())
	{
		if (itr->second.empty())
		{
			s2e()->getWarningsStream() << "Vector of signals was empty when trying to find interrupt for IRET to 0x" <<
					hexval(eip) << '\n';
		}
		else
		{
			InterruptReturnSignal returnSignal = itr->second.back();
			s2e()->getDebugStream() << "Received IRET for INT at 0x" << hexval(itr->first) << '\n';
			returnSignal.emit(state, pc);
			itr->second.pop_back();
		}

	}
	else
	{
		s2e()->getDebugStream() << "no return signal for IRET at 0x" << hexval(eip) << " found" << '\n';
	}

	s2e()->getDebugStream() << "IRET at 0x" << hexval(pc) << " returning to " << hexval(eip) << '\n';
}

void InterruptMonitor::onInterrupt(S2EExecutionState* state, uint64_t pc)
{
	char insnByte;
	int intNum = -1;
	
	//s2e()->getMemoryTypeStream() << "In the InterruptMonitor::onInterrupt, the flag_isInterceptedModules = [ " << flag_isInterceptedModules << " ]" << '\n';
	if(!flag_isInterceptedModules){
	//	return;
	}

	DECLARE_PLUGINSTATE(InterruptMonitorState, state);

	if (!state->readMemoryConcrete(pc, &insnByte, 1))
	{
		s2e()->getWarningsStream() << "Could not read interrupt instruction at 0x" << hexval(pc) << '\n';// << std::dec << '\n';
		return;
	}

	if ((insnByte & 0xFF) == 0xCC)
	{
		intNum = 3;
	}
	else if ((insnByte & 0xFF) == 0xCD)
	{
		unsigned char intNumByte;

		if (!state->readMemoryConcrete(pc + 1, &intNumByte, 1))
		{
			s2e()->getWarningsStream() << "Could not read interrupt index at 0x" << hexval(pc)<< '\n';// << std::dec << '\n';
			return;
		}

		intNum = (int) intNumByte;
	}
	else
	{
		/* Invalid Opcode */
		s2e()->getWarningsStream() << "Unexpected opcode 0x" << hexval((unsigned int) insnByte)	<< " at 0x" << hexval(pc) << ", expected 0xcc or 0xcd" << '\n';//std::dec << '\n';
		return;
	}

	assert(intNum != -1);

	//Generate a signal that will be called once the interrupt returns
	//TODO: make object handling of signals more efficient

	plgState->m_returnSignals[pc + 2].push_back(InterruptReturnSignal());
	InterruptReturnSignal& returnSignal = plgState->m_returnSignals[pc + 2].back();

	//Find and notify signals for this interrupt no
	std::map<int, InterruptSignal>::iterator itr = plgState->m_signals.find(intNum);

	if (itr != plgState->m_signals.end())
	{
		itr->second.emit(state, pc, intNum, returnSignal);
	}

	//Always notify signal at -1
	plgState->m_signals[-1].emit(state, pc, intNum, returnSignal);

	//s2e()->getDebugStream() << "Received interrupt 0x" << hexval(intNum) << " at 0x" << hexval(pc) << '\n';
}

InterruptMonitor::InterruptMonitor(S2E* s2e) : Plugin(s2e)
{
	// TODO Auto-generated constructor stub
}

InterruptMonitor::~InterruptMonitor() {
	// TODO Auto-generated destructor stub
}

InterruptMonitorState* InterruptMonitorState::clone() const
{
    InterruptMonitorState *ret = new InterruptMonitorState(*this);
//    m_plugin->s2e()->getDebugStream() << "Forking FunctionMonitorState ret=" << std::hex << ret << '\n';
    assert(ret->m_returnSignals.size() == m_returnSignals.size());
    return ret;
}

PluginState *InterruptMonitorState::factory(Plugin *p, S2EExecutionState *s)
{
	InterruptMonitorState *ret = new InterruptMonitorState();
    ret->m_plugin = static_cast<InterruptMonitor*>(p);
    return ret;
}

} //namespace plugins
} //namespace s2e

