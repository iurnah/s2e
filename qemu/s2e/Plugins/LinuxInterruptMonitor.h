/*
 * LinuxInterruptMonitor.h
 *
 *  Created on: Dec 8, 2011
 *      Author: zaddach
 */

#ifndef _S2E_PLUGINS_INTERRUPTMONITOR_H_
#define _S2E_PLUGINS_INTERRUPTMONITOR_H_

#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/LinuxExecutionDetector.h>
#include <s2e/Plugins/LinuxCodeSelector.h>

#include <map>
#include <vector>

namespace s2e {
namespace plugins {

class LinuxInterruptMonitor : public Plugin
{
	S2E_PLUGIN

public:
	typedef sigc::signal< void, S2EExecutionState*, uint64_t > InterruptReturnSignal;
	typedef sigc::signal< void, S2EExecutionState*, uint64_t, int> InterruptSignal;
	typedef std::map< uint32_t, std::vector< InterruptReturnSignal > > ReturnSignalsMap;


	LinuxInterruptMonitor(S2E* s2e);
	virtual ~LinuxInterruptMonitor();

	void initialize();

	InterruptSignal& getInterruptSignal(S2EExecutionState* state, int interrupt);

	void onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule);
	void slotTranslateBlockEnd(ExecutionSignal*, S2EExecutionState *state,
	                               TranslationBlock *tb, uint64_t pc,
	                               bool, uint64_t);
/*
	void onModuleTranslateBlockEnd(
								ExecutionSignal *signal,
								S2EExecutionState* state,
								const ModuleDescriptor& md,
								TranslationBlock *tb,
								uint64_t endPc,
								bool staticTarget,
								uint64_t targetPc);
*/
	void onTranslateJumpStart(ExecutionSignal *signal,
	                                             S2EExecutionState *state,
	                                             TranslationBlock * tb,
	                                             uint64_t pc, int jump_type);

	void onInterruptReturn(S2EExecutionState* state, uint64_t pc);
	void onInterrupt(S2EExecutionState*, uint64_t);
	InterruptSignal onInterruptIntercepted; //signal

private:
//	bool m_initialized;
	bool flag_isInterceptedModules;
	std::set<std::string> m_interceptedModules;
	LinuxExecutionDetector *m_executionDetector;
	LinuxCodeSelector *m_LinuxCodeSelector;
	sigc::connection m_onTranslateBlockEnd;

};

class LinuxInterruptMonitorState : public PluginState
{
private:
	LinuxInterruptMonitor::ReturnSignalsMap m_returnSignals;
	LinuxInterruptMonitor* m_plugin;
public:
	std::map<int, LinuxInterruptMonitor::InterruptSignal> m_signals;

	virtual LinuxInterruptMonitorState* clone() const;
	static PluginState *factory(Plugin *p, S2EExecutionState *s);

	friend class LinuxInterruptMonitor;
};

} //namespace plugins
} //namespace s2e

#endif /* INTERRUPTMONITOR_H_ */
