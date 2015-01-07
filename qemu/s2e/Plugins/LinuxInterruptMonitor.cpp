/*
 * LinuxInterruptMonitor.cpp
 *
 *  Created on: Dec 8, 2011
 *      Author: zaddach
 */
/* 
 * Modified on: Sept 26, 2014
 * 
 *		By: Rui 
 * 
 */


extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include <vector>
#include <map>

#include <s2e/S2E.h>
//#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/LinuxInterruptMonitor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

using std::vector;
using std::map;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxInterruptMonitor, "software interrupt monitoring plugin", 
				"LinuxInterruptMonitor", "LinuxExecutionDetector", "LinuxCodeSelector");


void LinuxInterruptMonitor::initialize()
{
	m_executionDetector = (LinuxExecutionDetector*)s2e()->getPlugin("LinuxExecutionDetector");
    assert(m_executionDetector);
	m_LinuxCodeSelector = (LinuxCodeSelector*)s2e()->getPlugin("LinuxCodeSelector");	
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
			s2e()->getWarningsStream() << "LinuxInterruptMonitor: Module " << *it << " is inserted in m_interceptedModules!\n";
        }else {
            s2e()->getWarningsStream() << "LinuxInterruptMonitor: " << "Module " << *it << " is not configured\n";
            exit(-1);
        }
    }

	//we use onModuleTransitionSelector from LinuxCodeSelector to enable signal
	//emition from the interested module.
	m_LinuxCodeSelector->onModuleTransitionSelector.connect(sigc::mem_fun(*this, 
							&LinuxInterruptMonitor::onModuleTransition));

}

// This member function connect onTranslateBlockEnd from CorePlugins to make
// sure we intercept interrupt instruction inside the module we are interested,
// and ignore all other interrupt signals.
void LinuxInterruptMonitor::onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule)
{
	//if current is in the interceptedModules, we intercept the interrupt instructions.
	if(m_interceptedModules.find(currentModule->Name) != m_interceptedModules.end()){
		if(!m_onTranslateBlockEnd.connected()){
			m_onTranslateBlockEnd = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
							sigc::mem_fun(*this, &LinuxInterruptMonitor::slotTranslateBlockEnd));

			s2e()->getDebugStream() << "LinuxInterruptMonitor::onTranslateBlockEnd: Disconnect onTranslateBlockEnd!" << "\n";
		}
	}else{//disable intercept the interrupt signals.
		m_onTranslateBlockEnd.disconnect();		
		s2e()->getDebugStream() << "LinuxInterruptMonitor::onTranslateBlockEnd: Disconnect onTranslateBlockEnd!" << "\n";
	}
}

// When this member function has been called, it connect to the runtime signal
// that once executed, will emit signals to S2E plugin to involke the callback
// function onInterrupt()
void LinuxInterruptMonitor::slotTranslateBlockEnd(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc, bool, uint64_t)
{
	if (tb->s2e_tb_type == TB_INTERRUPT) 
	{
		signal->connect(sigc::mem_fun(*this, &LinuxInterruptMonitor::onInterrupt));
	}
}

// This member function has everything it needed to parse the interrupt
// instruction in order to get the interrupt number, and finally emit the
// interruptSignall
void LinuxInterruptMonitor::onInterrupt(S2EExecutionState* state, uint64_t pc)
{

	DECLARE_PLUGINSTATE(LinuxInterruptMonitorState, state);

	char insnByte;
	int intNum = -1;

	if (!state->readMemoryConcrete(pc, &insnByte, 1))
	{
		s2e()->getWarningsStream() << "Could not read interrupt instruction at 0x" 
				<< hexval(pc) << '\n';// << std::dec << '\n';

		return;
	}

	if ((insnByte & 0xFF) == 0xCC) //INT 3, debugging purpose interrupt
	{
		intNum = 3;
	}
	else if ((insnByte & 0xFF) == 0xCD) //general interrupt instructions 
	{
		unsigned char intNumByte;

		if (!state->readMemoryConcrete(pc + 1, &intNumByte, 1))
		{
			s2e()->getWarningsStream() << "Could not read interrupt index at 0x" 
					<< hexval(pc)<< '\n';// << std::dec << '\n';
			return;
		}

		intNum = (int) intNumByte;
	}
	else
	{
		/* Invalid Opcode */
		s2e()->getWarningsStream() << "Unexpected opcode 0x" 
				<< hexval((unsigned int) insnByte)	<< " at 0x" 
				<< hexval(pc) << ", expected 0xcc or 0xcd" << '\n';

		return;
	}

	assert(intNum != -1);

	s2e()->getDebugStream(state) << "LinuxInterruptMonitor::Received interrupt " 
				<< hexval(intNum) << " at 0x" << hexval(pc) << '\n';

		//TODO emit interrupt signal, the signal should managed by the plugin state, 
		//it should be in the current plugin state 
		//candidate signal parameters: state, pc, intNum, eax_val, returnSignal
	std::map<int, InterruptSignal>::iterator itr = plgState->m_signals.find(intNum);
	if(itr != plgState->m_signals.end()){
		itr->second.emit(state, pc, intNum);
	}else 
		s2e()->getDebugStream(state) << "LinuxInterruptMonitor::InterruptSignal didn't emitted for interrupt =" 
				<< hexval(intNum) << " at 0x" << hexval(pc) << '\n';

	//plgState->m_signals[-1].emit(state, pc, intNum, returnSignal);
}

LinuxInterruptMonitor::InterruptSignal& LinuxInterruptMonitor::getInterruptSignal(S2EExecutionState* state, int interrupt)
{

	DECLARE_PLUGINSTATE(LinuxInterruptMonitorState, state);

	assert (interrupt >= -1 && interrupt <= 0xff);

	return plgState->m_signals[interrupt];
	
}

LinuxInterruptMonitor::LinuxInterruptMonitor(S2E* s2e) : Plugin(s2e)
{
	// TODO Auto-generated constructor stub
}

LinuxInterruptMonitor::~LinuxInterruptMonitor() {
	// TODO Auto-generated destructor stub
}

LinuxInterruptMonitorState* LinuxInterruptMonitorState::clone() const
{
    LinuxInterruptMonitorState *ret = new LinuxInterruptMonitorState(*this);
//    m_plugin->s2e()->getDebugStream() << "  ret=" << stdhex << ret << '\n';
    assert(ret->m_returnSignals.size() == m_returnSignals.size());
    return ret;
}

PluginState *LinuxInterruptMonitorState::factory(Plugin *p, S2EExecutionState *s)
{
	LinuxInterruptMonitorState *ret = new LinuxInterruptMonitorState();
    ret->m_plugin = static_cast<LinuxInterruptMonitor*>(p);
    return ret;
}

} //namespace plugins
} //namespace s2e

