/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

/**
 *  This plugin tracks the modules which are being executed at any given point.
 *  A module is a piece of code defined by a name. Currently the pieces of code
 *  are derived from the actual executable files reported by the OS monitor.
 *  TODO: allow specifying any kind of regions.
 *
 *  XXX: distinguish between processes and libraries, which should be tracked in all processes.
 *
 *  XXX: might translate a block without instrumentation and reuse it in instrumented part...
 *
 *  NOTE: it is not possible to track relationships between modules here.
 *  For example, tracking of a library of a particular process. Instead, the
 *  plugin tracks all libraries in all processes. This is because the instrumented
 *  code can be shared between different processes. We have to conservatively instrument
 *  all code, otherwise if some interesting code is translated first within the context
 *  of an irrelevant process, there would be no detection instrumentation, and when the
 *  code is executed in the relevant process, the module execution detection would fail.
 */
//#define NDEBUG


extern "C" {
#include "config.h"
#include "qemu-common.h"
#include "cpu.h"
extern struct CPUX86State *env;
}


#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/s2e_qemu.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Opcodes.h>

#include "LinuxExecutionDetector.h"
#include <assert.h>
#include <sstream>

using namespace s2e;
using namespace s2e::plugins;

/* LinuxExecutionDetector didn't import LinuxMonitor */
S2E_DEFINE_PLUGIN(LinuxExecutionDetector,
                  "Plugin for monitoring module execution",
                  "LinuxExecutionDetector",
                  "Interceptor");

LinuxExecutionDetector::~LinuxExecutionDetector()
{

}

void LinuxExecutionDetector::initialize()
{
    m_LinuxMonitor = (OSMonitor*)s2e()->getPlugin("Interceptor");
    assert(m_LinuxMonitor);

    m_LinuxMonitor->onModuleLoad.connect(
        sigc::mem_fun(*this, &LinuxExecutionDetector::moduleLoadListener));

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &LinuxExecutionDetector::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &LinuxExecutionDetector::onTranslateBlockEnd));

    initializeConfiguration();
}

void LinuxExecutionDetector::initializeConfiguration()
{
	ConfigFile * cfg = s2e()->getConfig();

	ConfigFile::string_list keyList = cfg->getListKeys(getConfigKey());
	if (keyList.size() == 0) {
        s2e()->getWarningsStream() <<  "LinuxExecutionDetector: no configuration keys!" << '\n';
    }

    m_TrackAllModules = cfg->getBool(getConfigKey() + ".trackAllModules");
    m_ConfigureAllModules = cfg->getBool(getConfigKey() + ".configureAllModules");

    foreach2(it, keyList.begin(), keyList.end()) {
        if (*it == "trackAllModules"  || *it == "configureAllModules") {
            continue;
        }

        ModuleExecutionCfg d;
        std::stringstream s;
        s << getConfigKey() << "." << *it << ".";
		if(*it == "init_env_id")
	        d.id = "init_env.so";
		else if(*it == "libc")
			d.id = "libc-2.13.so";
		else
			d.id = *it;

        bool ok = false;
        d.moduleName = cfg->getString(s.str() + "moduleName", "", &ok);
        if (!ok) {
            s2e()->getWarningsStream() << "You must specifiy " << s.str() + "moduleName" << '\n';
            exit(-1);
        }

        d.kernelMode = cfg->getBool(s.str() + "kernelMode", false, &ok);
        if (!ok) {
            s2e()->getWarningsStream() << "You must specifiy " << s.str() + "kernelMode" << '\n';
            exit(-1);
        }


        s2e()->getDebugStream() << "LinuxExecutionDetector: " <<
                "id=" << d.id << " " <<
                "moduleName=" << d.moduleName << " " <<
				"kernelMode=" << d.kernelMode << " " <<
                "context=" << d.context  << '\n';

        if (m_ConfiguredModulesName.find(d) != m_ConfiguredModulesName.end()) {
            s2e()->getWarningsStream() << "ModuleExecutionDetector: " <<
                    "module names must be unique!" << '\n';
            exit(-1);
        }

        m_ConfiguredModulesName.insert(d);
    }
}

/**********************************************************************/ 
/*
 * 1. Check the module correctness as to the Monitor passed and configured by configure file.
 * 2. Maintain a set of configured modules and non-configured modules, 
 */

/* after calling the moduleLoadListener, we have m_Descriptors and
 * m_NotTrackedDescriptors, the former is to hold the module that interested,
 * and the later is hold the modules that will be tracked, but out of
 * interests. i.e. It is not be notified, but is necessary to track in order for the
 * detector to work 
 *
 * configured module = notified module
 * tracked modules = module that tracked by LinuxExecutionDetector */
void LinuxExecutionDetector::moduleLoadListener(
    S2EExecutionState* state,
    const ModuleDescriptor &module)
{
    DECLARE_PLUGINSTATE(LinuxModuleTransitionState, state);

    //If module name matches the configured ones, activate.
    s2e()->getDebugStream(state) << "LinuxExecutionDetector: " 
			<< "Module "  << module.Name << " is loaded" 
			<< ", Base=" << hexval(module.NativeBase) //base
			<< ", limit=" << hexval(module.LoadBase) //limit 
			<< ", Size=" << hexval(module.Size) << '\n';


    ModuleExecutionCfg cfg;
    cfg.moduleName = module.Name;

	/* set all module as interested modules, ignore other configure entries */
    if (m_ConfigureAllModules) {
        if (plgState->exists(&module, true)) { //test whether in the m_Descriptors
            s2e()->getDebugStream(state) << "LinuxExecutionDetector: [ALREADY REGISTERED!]" << '\n';
        }else {
            s2e()->getDebugStream(state) << "LinuxExecutionDetector: [REGISTERING...]" << '\n';
            plgState->loadDescriptor(module, true); //add to the m_Descriptors
        }
        return;
    }

	/* load the configured module to m_Descriptors as interested modules */
    ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(cfg);
    if (it != m_ConfiguredModulesName.end()) {
        if (plgState->exists(&module, true)) {
            s2e()->getDebugStream(state) << "LinuxExecutionDetector(false): [configured ID =" 
					<< (*it).id << "] already loaded." << '\n';
        }else {
            s2e()->getDebugStream(state) << "LinuxExecutionDetector(false): [load configured ID=" 
					<< (*it).id << "]" << '\n';
            plgState->loadDescriptor(module, true); //add to the m_Descriptors
        }
        return;
    }

	/* load the not configured modules in to m_NotTrackedDescriptors as not
	 * interested modules*/
    if (m_TrackAllModules) {
        if (!plgState->exists(&module, false)) {
            s2e()->getDebugStream(state) << "LinuxExecutionDetector: Register the not configured module=" 
					<< module.Name << '\n';
            plgState->loadDescriptor(module, false);//add to the m_NotTrackedDescriptors
            //onModuleLoad.emit(state, module);
			//enable when necessary, it is different from the one from
			//RawMonitor.
        }
        return;
    }
}

/* We can increase the granuality by using the onTranslateInstructionStart,
 * since we only need to tell which module we are at to facilitate CodeSelector,
 * we can more efficiently implement this onTranslateBlockStart */
void LinuxExecutionDetector::onTranslateBlockStart(
    ExecutionSignal *signal,
    S2EExecutionState *state,
    TranslationBlock *tb,
    uint64_t pc)
{
	DECLARE_PLUGINSTATE(LinuxModuleTransitionState, state);

	uint64_t pid = m_LinuxMonitor->getPid(state, pc);
	const ModuleDescriptor * currentModule = plgState->getDescriptor(pid, pc);
	/* this getDescriptor method should be able to return the module based on
	 * its pid and PC value */

	if(currentModule){
//		s2e()->getDebugStream() << "LinuxExecutionDetector::onTranslateBlockStart: currentModule: Pid=" << currentModule->Pid << " name=" << currentModule->Name << " PC=" << hexval(pc) << '\n'; 

		/* connected upon translation, emit this signal in execution time */
		signal->connect(sigc::mem_fun(*this, &LinuxExecutionDetector::onExecution));
	}
}

/* */
void LinuxExecutionDetector::onTranslateBlockEnd(
		ExecutionSignal *signal,
		S2EExecutionState *state,
		TranslationBlock *tb,
		uint64_t endPc,
		bool staticTarget,
		uint64_t targetPc)
{
	DECLARE_PLUGINSTATE(LinuxModuleTransitionState, state);

	uint64_t pid = m_LinuxMonitor->getPid(state, endPc);
	const ModuleDescriptor * currentModule = plgState->getDescriptor(pid, endPc);

	if(!currentModule){
		return;
	}
	
	if(staticTarget){
		const ModuleDescriptor *targetModule = 
				plgState->getDescriptor(pid, targetPc);

		if(targetModule != currentModule){
			signal->connect(sigc::mem_fun(*this, 
									&LinuxExecutionDetector::onExecution));
		}

	}else {
		signal->connect(sigc::mem_fun(*this, 
								&LinuxExecutionDetector::onExecution));
	}

	if(currentModule){
		onModuleTranslateBlockEnd.emit(signal, state, *currentModule, tb, endPc, staticTarget, targetPc);
		//s2e()->getDebugStream() << "LinuxExecutionDetector::onTranslateBlockEnd: currentModule=" << currentModule->Name << " PC=" << hexval(endPc) << '\n';
	}

}

void LinuxExecutionDetector::onExecution(
    S2EExecutionState *state, uint64_t pc)
{

	DECLARE_PLUGINSTATE(LinuxModuleTransitionState, state);

	uint64_t pid = m_LinuxMonitor->getPid(state, pc);
	const ModuleDescriptor * currentModule = plgState->getDescriptor(pid, pc);

//	s2e()->getDebugStream() << "LinuxExecutionDetector::onExecution: currentModule=" << currentModule->Name << " PC=" << hexval(pc) << '\n';

	if(plgState->m_PreviousModule != currentModule){
#if 0
		std::string prev_name;

		if(plgState->m_PreviousModule){
			prev_name = plgState->m_PreviousModule->Name;
		}else {
			prev_name = "NULL";
		}

		s2e()->getDebugStream(state) << "LinuxModuleTransitionState::onExecution: Switch module from " <<
				prev_name << " to " << currentModule->Name << " PC=" << hexval(pc) << '\n';

		if(currentModule){
			s2e()->getDebugStream(state) << "LinuxModuleTransitionState::onExecution: Entered Module " << 
					currentModule->Name << " PC=" << hexval(pc) << '\n';
		}else {
			s2e()->getDebugStream(state) << "LinuxModuleTransitionState::onExecution: Entered unknown module, PC=" << hexval(pc) << '\n';
		}
#endif
		onModuleTransition.emit(state, plgState->m_PreviousModule, currentModule);

		plgState->m_PreviousModule = currentModule;

	}
//	s2e()->getDebugStream(state) << "LinuxModuleTransitionState::onExecution: Keep Execute same module, PC=" << hexval(pc) << '\n';
}

bool LinuxModuleTransitionState::loadDescriptor(const ModuleDescriptor &desc, bool track)
{
    if (track) {
        m_Descriptors.insert(new ModuleDescriptor(desc));
    }else {
        if (m_NotTrackedDescriptors.find(&desc) == m_NotTrackedDescriptors.end()) {
            m_NotTrackedDescriptors.insert(new ModuleDescriptor(desc));
        }
        else {
            return false;
        }
    }
    return true;
}

bool LinuxModuleTransitionState::exists(const ModuleDescriptor *desc, bool tracked) const
{
    bool ret;
    ret = m_Descriptors.find(desc) != m_Descriptors.end();
    if (ret) { //exist in the configured modules.
        return ret;
    }

    if (tracked) { //if not exist in the configure modules and it is tracked, return false 
        return false;
    }

	//if not exist in the configured modules and not tracked, test whether it is
	//in the not tracked descriptor set, if yes, return ture. if no, return
	//false. 
    return m_NotTrackedDescriptors.find(desc) != m_NotTrackedDescriptors.end();
}

const ModuleDescriptor *LinuxModuleTransitionState::getDescriptor(uint64_t pid, uint64_t pc) const
{
	foreach2(it, m_Descriptors.begin(), m_Descriptors.end()) {
		if(pid == (*it)->Pid && pc > (*it)->NativeBase && pc < (*it)->LoadBase)
			return *it;
		}

	foreach2(it, m_NotTrackedDescriptors.begin(), m_NotTrackedDescriptors.end()) {
		if(pid == (*it)->Pid && pc > (*it)->NativeBase && pc < (*it)->LoadBase)
			return *it;
		}

	return NULL;
}

/* used by client plugin to validate the module is configured by the parent
 * plugin */
bool LinuxExecutionDetector::isModuleConfigured(const std::string &moduleName)const
{
	ModuleExecutionCfg modules;
	modules.moduleName = moduleName;

	return m_ConfiguredModulesName.find(modules) != m_ConfiguredModulesName.end();
}

/* this is for check whether the configured module id is in the m_Intercepted set */
const std::string *LinuxExecutionDetector::getModuleId(const ModuleDescriptor &desc) const
{
	ModuleExecutionCfg cfg;
	cfg.moduleName = desc.Name;

	ConfiguredModulesByName::iterator it = m_ConfiguredModulesName.find(cfg);
	if(it == m_ConfiguredModulesName.end()){
		return NULL;
	}
	return &(*it).id;
}

LinuxModuleTransitionState::LinuxModuleTransitionState()
{
    m_PreviousModule = NULL; //TODO: initial to a unknow module.
    m_CachedModule = NULL;
}

LinuxModuleTransitionState::~LinuxModuleTransitionState()
{
    foreach2(it, m_Descriptors.begin(), m_Descriptors.end()) {
        delete *it;
    }

    foreach2(it, m_NotTrackedDescriptors.begin(), m_NotTrackedDescriptors.end()) {
        delete *it;
    }
}

LinuxModuleTransitionState* LinuxModuleTransitionState::clone() const
{
    LinuxModuleTransitionState *ret = new LinuxModuleTransitionState();

    foreach2(it, m_Descriptors.begin(), m_Descriptors.end()) {
        ret->m_Descriptors.insert(new ModuleDescriptor(**it));
    }

    foreach2(it, m_NotTrackedDescriptors.begin(), m_NotTrackedDescriptors.end()) {
        //assert(*it != m_CachedModule && *it != m_PreviousModule);
        ret->m_NotTrackedDescriptors.insert(new ModuleDescriptor(**it));
		//TODO shouldn't be make a pair fisrt then insert?
    }

    if (m_CachedModule) {
        DescriptorSet::iterator it = ret->m_Descriptors.find(m_CachedModule);
        if(it != ret->m_Descriptors.end())
			ret->m_CachedModule = *it;
    }

    if (m_PreviousModule) {
        DescriptorSet::iterator it = ret->m_Descriptors.find(m_PreviousModule);
        if(it != ret->m_Descriptors.end())
			ret->m_PreviousModule = *it;
    }

    return ret;
}

PluginState* LinuxModuleTransitionState::factory(Plugin *p, S2EExecutionState *state)
{
    LinuxModuleTransitionState *s = new LinuxModuleTransitionState();

    p->s2e()->getDebugStream() << "Creating initial module transition state" << '\n';

    return s;
}
