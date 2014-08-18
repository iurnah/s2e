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

extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include "FunctionMonitor.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(X86FunctionMonitor, "Function calls/returns monitoring plugin", "X86FunctionMonitor", "ModuleExecutionDetector");

void X86FunctionMonitor::initialize()
{
    m_monitor = static_cast<OSMonitor*>(s2e()->getPlugin("Interceptor"));

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
			s2e()->getWarningsStream() << "X86FunctionMonitor: Module " << *it << " is inserted m_interceptedModules!\n";
        }else {
            s2e()->getWarningsStream() << "X86FunctionMonitor: " << "Module " << *it << " is not configured\n";
            exit(-1);
        }
    }

    m_executionDetector->onModuleTransition.connect(
        sigc::mem_fun(*this, &X86FunctionMonitor::onModuleTransition));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &X86FunctionMonitor::slotTranslateBlockEnd));

    s2e()->getCorePlugin()->onTranslateJumpStart.connect(
            sigc::mem_fun(*this, &X86FunctionMonitor::slotTranslateJumpStart));

#if 0
    //Cannot do this here, because we do not have an execution state at this point.
    if(s2e()->getConfig()->getBool(getConfigKey() + ".enableTracing")) {
        getCallSignal(0, 0)->connect(sigc::mem_fun(*this,
                                     &X86FunctionMonitor::slotTraceCall));
    }
#endif
	s2e()->getDebugStream() << "X86FunctionMonitor: Plugin Initialized" << '\n';
}

//XXX: Implement onmoduleunload to automatically clear all call signals
X86FunctionMonitor::CallSignal* X86FunctionMonitor::getCallSignal(
        S2EExecutionState *state,
        uint64_t eip, uint64_t cr3)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);

    return plgState->getCallSignal(eip, cr3);
}

void X86FunctionMonitor::slotTranslateBlockEnd(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc, bool, uint64_t)
{
	//s2e()->getDebugStream() << "X86FunctionMonitor: slotTranslateBlockEnd!!!" << '\n';
	/* We intercept all call and ret translation blocks */
    if (tb->s2e_tb_type == TB_CALL || tb->s2e_tb_type == TB_CALL_IND){
        signal->connect(sigc::mem_fun(*this,
                            &X86FunctionMonitor::slotCall));
		uint32_t ebp;
		uint32_t esp;
		state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EBP]), &(ebp), sizeof(uint32_t));
		state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]), &(esp), sizeof(uint32_t));
		//TODO:here we get the diferent EBP value.

		//s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor: slotCall Connected!!! PC = " << hexval(pc) << '\n';
    }
}

void X86FunctionMonitor::slotTranslateJumpStart(ExecutionSignal *signal,
                                             S2EExecutionState *state,
                                             TranslationBlock *,
                                             uint64_t, int jump_type)
{
    if(jump_type == JT_RET || jump_type == JT_LRET) {
        signal->connect(sigc::mem_fun(*this,
                            &X86FunctionMonitor::slotRet));
    }
}

void X86FunctionMonitor::onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule)
{
    if (!currentModule) {
        //state->disableForking();
		flag_isInterceptedModules = false;
		s2e()->getMemoryTypeStream(state) << "set the flag to false when the current module if NULL" << '\n';
        return;
    }
	
	if(prevModule == NULL){
		s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor::onModuleTransition: prevModule=NULL" << '\n';
	}else 
		s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor::onModuleTransition: prevModule=" << 
			prevModule->Name << " currentModule=" << currentModule->Name << '\n';

    const std::string *id = m_executionDetector->getModuleId(*currentModule);
    if (m_interceptedModules.find(*id) == m_interceptedModules.end()) {
        //state->disableForking(); //in s2e-out-38, this never reached.
		flag_isInterceptedModules = false;
		s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor::set the flag to false because of enter not intercept module" << '\n';
        return;
    }

	s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor::set the flag to true because of enter the moduleId = " << *id << '\n';
	flag_isInterceptedModules = true; //TODO: is there a fourth possible of transition? 
}

void X86FunctionMonitor::slotCall(S2EExecutionState *state, uint64_t pc)
{
	//TODO: here we check the module is the one we configured.
	if(!flag_isInterceptedModules){
		return;
	}	
	
	uint32_t ebp;
   	uint32_t esp;
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(ebp), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(esp), sizeof (uint32_t) );

	//FIXME:Here I can read the different ESP and EBP values.
	s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor: slotCall EBP = " << hexval(ebp) << '\n';
	s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor: slotCall ESP = " << hexval(esp) << '\n';
	s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor: slotCall PC  = " << hexval(pc) << '\n';
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);
#if 0
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(ebp), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(esp), sizeof (uint32_t) );

	//FIXME:Here I can read the different ESP and EBP values.
	s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor: slotCall EBP = " << hexval(ebp) << " getBp = " << hexval(state->getBp()) << '\n';
	s2e()->getMemoryTypeStream(state) << "X86FunctionMonitor: slotCall ESP = " << hexval(esp) << " getSp = " << hexval(state->getSp()) << '\n';
#endif
    return plgState->slotCall(state, pc);
}

void X86FunctionMonitor::disconnect(S2EExecutionState *state, const ModuleDescriptor &desc)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);

    return plgState->disconnect(desc);
}

//See notes for slotRet to see how to use this function.
void X86FunctionMonitor::eraseSp(S2EExecutionState *state, uint64_t pc)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);

    return plgState->slotRet(state, pc, false);
}

void X86FunctionMonitor::registerReturnSignal(S2EExecutionState *state, X86FunctionMonitor::ReturnSignal &sig)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);
    plgState->registerReturnSignal(state, sig);
}


void X86FunctionMonitor::slotRet(S2EExecutionState *state, uint64_t pc)
{
    DECLARE_PLUGINSTATE(X86FunctionMonitorState, state);

    return plgState->slotRet(state, pc, true);
}

#if 0
void X86FunctionMonitor::slotTraceCall(S2EExecutionState *state, X86FunctionMonitorState *fns)
{
    static int f = 0;

    X86FunctionMonitor::ReturnSignal returnSignal;
    returnSignal.connect(sigc::bind(sigc::mem_fun(*this, &X86FunctionMonitor::slotTraceRet), f));
    fns->registerReturnSignal(state, returnSignal);

    s2e()->getMessagesStream(state) << "Calling function " << f
                << " at " << hexval(state->getPc()) << std::endl;
    ++f;
}


void X86FunctionMonitor::slotTraceRet(S2EExecutionState *state, int f)
{
    s2e()->getMessagesStream(state) << "Returning from function "
                << f << std::endl;
}
#endif

X86FunctionMonitorState::X86FunctionMonitorState()
{

}

X86FunctionMonitorState::~X86FunctionMonitorState()
{

}

X86FunctionMonitorState* X86FunctionMonitorState::clone() const
{
    X86FunctionMonitorState *ret = new X86FunctionMonitorState(*this);
    m_plugin->s2e()->getDebugStream() << "X86FunctionMonitor: Forking FunctionMonitorState ret=" << hexval(ret) << '\n';
    assert(ret->m_returnDescriptors.size() == m_returnDescriptors.size());
    return ret;
}

PluginState *X86FunctionMonitorState::factory(Plugin *p, S2EExecutionState *s)
{
    X86FunctionMonitorState *ret = new X86FunctionMonitorState();
    ret->m_plugin = static_cast<X86FunctionMonitor*>(p);
    return ret;
}

X86FunctionMonitor::CallSignal* X86FunctionMonitorState::getCallSignal(
        uint64_t eip, uint64_t cr3)
{
    std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
            range = m_callDescriptors.equal_range(eip);

	CallDescriptorsMap::iterator it_new;
	if(range.first == range.second){//the signal doesn't exist, create one and insert to m_newCallDescriptors
		//m_plugin->s2e()->getMemoryTypeStream() << "X86FunctionMonitorState::getCallSignal return Nothing" << '\n';

	    CallDescriptor descriptor = { cr3, X86FunctionMonitor::CallSignal() };
		it_new = m_newCallDescriptors.insert(std::make_pair(eip, descriptor));
	}else { //if have it in the m_callDescriptors map, try to look for the callSignal, if not exist should XXX also XXX create one
		for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
			if(it->second.cr3 == cr3){ //find the signal for the eip and cr3
				return &it->second.signal;
			}else { //in this case, although the key(eip) exist in m_callDescriptors, but no mach cr3, have to create. same pc different process
				CallDescriptor descriptor = { cr3, X86FunctionMonitor::CallSignal() };
				it_new = m_newCallDescriptors.insert(std::make_pair(eip, descriptor));
			}
		}
	}

	return &it_new->second.signal; 

}

/* slotCall first need to check the pc in this call is the correct one, this pc
 * should from the signal parameter, if this pc(not eip) is not in the
 * m_callDescriptors map, it should just ignore */
void X86FunctionMonitorState::slotCall(S2EExecutionState *state, uint64_t pc)
{
    target_ulong cr3 = state->getPid();
    target_ulong eip = state->getPc();
	//uint64_t ebp = state->getBp();
	//uint64_t esp = state->getSp();
	//TODO:debug to check whether pc and eip value, to see whether they are able
	//to match to the imported function
	m_plugin->s2e()->getMemoryTypeStream(state) << "X86FunctionMonitorState::slotCall PC =" << hexval(pc) << '\n';
	m_plugin->s2e()->getMemoryTypeStream(state) << "X86FunctionMonitorState::slotCall eip=" << hexval(eip) << '\n';
	/* add the cached CallDescriptors to the m_callDescriptors map */	
    if (!m_newCallDescriptors.empty()) {
        m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
        m_newCallDescriptors.clear();
    }
#if 0
    /* Issue signals attached to all calls (eip==-1 means catch-all) */
    if (!m_callDescriptors.empty()) {
        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
                range = m_callDescriptors.equal_range((uint64_t)-1);
        for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            CallDescriptor cd = (*it).second;
            if (m_plugin->m_monitor) {
                cr3 = m_plugin->m_monitor->getPid(state, pc);
            }
            if(it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {
                cd.signal.emit(state, this);
			
				m_plugin->s2e()->getMemoryTypeStream(state) << "X86FunctionMonitorState: cd.signal.emitted!!!" << '\n';
            }
        }
        if (!m_newCallDescriptors.empty()) {
            m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
            m_newCallDescriptors.clear();
        }
    }
#endif

    /* Issue signals attached to specific calls */
    if (!m_callDescriptors.empty()) {
        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
                range = m_callDescriptors.equal_range(eip);
		/* FIXME: Problem might be here, eip is the pointer point to the call
		 * function, while the pc in the m_callDescriptors is only have the pc
		 * value to the function, we should distinguish those pc values. 
		 * 1. when the pc is the last instruction of the translation block, such as 8048508: call 80483d0 <read@plt>
		 * 2. when the pc is pointing to the instruction of the begining of the function, such as 80483d0 <read@plt> 
		 * 3. what is the pc passed by the ExecutionSignal, "pc of the instruction being translated", this pc is point to the last instruction in the tb.
		 * */
		 

/* this isn't necessary, since if the first == second, the for loop will not run once at all 
		if(range.first == range.second){
			m_plugin->s2e()->getMemoryTypeStream(state) << "X86FunctionMonitorState::slotCall equal_range didn't return any match !!!" << '\n';
		}else {
			m_plugin->s2e()->getMemoryTypeStream(state) << "X86FunctionMonitorState::slotCall equal_range(" << hexval(eip) << ") returned!!!" << '\n';
		}
*/
		//might cased by this for loop.
        for(CallDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            CallDescriptor cd = (*it).second;
            if (m_plugin->m_monitor) {
                cr3 = m_plugin->m_monitor->getPid(state, pc); // retrive cr3 to emit the correspondent signal
            }
			
			//Rui: this pc value passed from signal is correct, but the stack
			//pointer and the base pointer is not correct, TODO:because the it
			//is a state issue?
            if(it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {//so far, we never create with cr3 = -1

                cd.signal.emit(state, this);
	
				/*TODO: here EBP always same 
				uint32_t ebp, esp;
				state->readCpuRegisterConcrete(CPU_OFFSET (regs[R_EBP]), &(ebp), sizeof (uint32_t) );
				state->readCpuRegisterConcrete(CPU_OFFSET (regs[R_ESP]), &(esp), sizeof (uint32_t) );
				m_plugin->s2e()->getMemoryTypeStream(state) << "X86FunctionMonitorState::slotCall EBP = " << hexval(ebp) << '\n';
				m_plugin->s2e()->getMemoryTypeStream(state) << "X86FunctionMonitorState::slotCall ESP = " << hexval(esp) << '\n';
				//TODO: debug print to see whether the emit is trigged by find
				//the signal in the populated m_callDescriptors data structure
				m_plugin->s2e()->getMemoryTypeStream(state) << "X86FunctionMonitorState: cd.signal.emitted when eip="
						<< hexval(eip) << " and cr3=" << hexval(cr3) << '\n';
				*/
            }
        }

        if (!m_newCallDescriptors.empty()) {
            m_callDescriptors.insert(m_newCallDescriptors.begin(), m_newCallDescriptors.end());
            m_newCallDescriptors.clear();
        }
    }
}

/**
 *  A call handler can invoke this function to register a return handler.
 *  XXX: We assume that the passed execution state corresponds to the state in which
 *  this instance of FunctionMonitorState is used.
 */
void X86FunctionMonitorState::registerReturnSignal(S2EExecutionState *state, X86FunctionMonitor::ReturnSignal &sig)
{
    if(sig.empty()) {
        return;
    }

    target_ulong esp;

    bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]),
                                             &esp, sizeof esp);
    if(!ok) {
        m_plugin->s2e()->getWarningsStream(state)
            << "Function call with symbolic ESP!\n"
            << "  EIP=" << hexval(state->getPc()) << " CR3=" << hexval(state->getPid()) << '\n';
        return;
    }

    uint64_t pid = state->getPid();
    if (m_plugin->m_monitor) {
        pid = m_plugin->m_monitor->getPid(state, state->getPc());
    }
    ReturnDescriptor descriptor = {pid, sig };
    m_returnDescriptors.insert(std::make_pair(esp, descriptor));
}

/**
 *  When emitSignal is false, this function simply removes all the return descriptors
 * for the current stack pointer. This can be used when a return handler manually changes the
 * program counter and/or wants to exit to the cpu loop and avoid being called again.
 *
 *  Note: all the return handlers will be erased if emitSignal is false, not just the one
 * that issued the call. Also note that it not possible to return from the handler normally
 * whenever this function is called from within a return handler.
 */
void X86FunctionMonitorState::slotRet(S2EExecutionState *state, uint64_t pc, bool emitSignal)
{
    target_ulong cr3 = state->readCpuState(CPU_OFFSET(cr[3]), 8*sizeof(target_ulong));
    target_ulong esp;

   	//m_plugin->s2e()->getDebugStream() << "X86FunctionMonitorState: In the slotRet!!!" << '\n';

    bool ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ESP]),
                                             &esp, sizeof(target_ulong));
    if(!ok) {
        target_ulong eip = state->readCpuState(CPU_OFFSET(eip),
                                               8*sizeof(target_ulong));
        m_plugin->s2e()->getWarningsStream(state)
            << "Function return with symbolic ESP!" << '\n'
            << "  EIP=" << hexval(eip) << " CR3=" << hexval(cr3) << '\n';
        return;
    }

    if (m_returnDescriptors.empty()) {
        return;
    }

    //m_plugin->s2e()->getDebugStream() << "ESP AT RETURN 0x" << std::hex << esp <<
    //        " plgstate=0x" << this << " EmitSignal=" << emitSignal <<  std::endl;

    bool finished = true;
    do {
        finished = true;
        std::pair<ReturnDescriptorsMap::iterator, ReturnDescriptorsMap::iterator>
                range = m_returnDescriptors.equal_range(esp);
        for(ReturnDescriptorsMap::iterator it = range.first; it != range.second; ++it) {
            if (m_plugin->m_monitor) {
                cr3 = m_plugin->m_monitor->getPid(state, pc);
            }

            if(it->second.cr3 == cr3) {
                if (emitSignal) {
                    it->second.signal.emit(state);
                }
                m_returnDescriptors.erase(it);
                finished = false;
                break;
            }
        }
    } while(!finished);
}

void X86FunctionMonitorState::disconnect(const ModuleDescriptor &desc, CallDescriptorsMap &descMap)
{
    CallDescriptorsMap::iterator it = descMap.begin();
    while (it != descMap.end()) {
        uint64_t addr = (*it).first;
        const CallDescriptor &call = (*it).second;
        if (desc.Contains(addr) && desc.Pid == call.cr3) {
            CallDescriptorsMap::iterator it2 = it;
            ++it;
            descMap.erase(it2);
        }else {
            ++it;
        }
    }
}

//Disconnect all address that belong to desc.
//This is useful to unregister all handlers when a module is unloaded
void X86FunctionMonitorState::disconnect(const ModuleDescriptor &desc)
{

    disconnect(desc, m_callDescriptors);
    disconnect(desc, m_newCallDescriptors);

    //XXX: we assume there are no more return descriptors active when the module is unloaded
}


} // namespace plugins
} // namespace s2e
