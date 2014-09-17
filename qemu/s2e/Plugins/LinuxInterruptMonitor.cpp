/*
 * LinuxInterruptMonitor.cpp
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
#include <s2e/Plugins/LinuxInterruptMonitor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

using std::vector;
using std::map;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxInterruptMonitor, "software interrupt monitoring plugin", "LinuxInterruptMonitor", "LinuxExecutionDetector", "LinuxCodeSelector");


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

	m_LinuxCodeSelector->onModuleTransitionSelector.connect(sigc::mem_fun(*this, &LinuxInterruptMonitor::onModuleTransition));
}

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
		}
	}else{//disable intercept the interrupt signals.
		s2e()->getDebugStream() << "LinuxInterruptMonitor::error in configure intercepted module" << "\n";
		m_onTranslateBlockEnd.disconnect();		
	}
}

//TODO: add a exitModule() function and corresponding siganl to disconnect the
//signal

void LinuxInterruptMonitor::slotTranslateBlockEnd(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc, bool, uint64_t)
{
	if (tb->s2e_tb_type == TB_INTERRUPT) //XXX: Currently not be able to detect TB_INTERRUPT
	{
		signal->connect(sigc::mem_fun(*this, &LinuxInterruptMonitor::onInterrupt));
	}
}

void LinuxInterruptMonitor::onInterrupt(S2EExecutionState* state, uint64_t pc)
{
	char insnByte;
	int intNum = -1;

	if(!flag_isInterceptedModules){
	//	return;
	}

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
	if(intNum == 0x80){
		s2e()->getDebugStream() << "LinuxInterruptMonitor::Received interrupt " << hexval(intNum) << " at 0x" << hexval(pc) << '\n';
	}
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
//    m_plugin->s2e()->getDebugStream() << "Forking FunctionMonitorState ret=" << std::hex << ret << '\n';
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

