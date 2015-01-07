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

#ifndef S2E_PLUGINS_MEMTRACER_H
#define S2E_PLUGINS_MEMTRACER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/Opcodes.h>
#include <string>
#include <s2e/Plugins/LinuxExecutionDetector.h>
#include <s2e/Plugins/LinuxCodeSelector.h>
#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>


namespace s2e{
namespace plugins{


/** Handler required for KLEE interpreter */
class LinuxMemoryTracer : public Plugin
{
    S2E_PLUGIN

public:
    LinuxMemoryTracer(S2E* s2e);

    void initialize();

private:
	typedef std::multimap<uint32_t, uint64_t> overWrittenAddressesId;//without isolate states.
	//typedef std::multimap<uint32_t, uint64_t> overWrittenAddressesState;//for perstate case.

    LinuxExecutionDetector *m_executionDetector;
    LinuxCodeSelector *m_LinuxCodeSelector;

	std::set<std::string> m_interceptedModules;

    sigc::connection m_memoryMonitor;
    sigc::connection m_privilegeTracking;

	overWrittenAddressesId m_overWrittenAddressesId;

    uint64_t m_timeTrigger;
    uint64_t m_elapsedTics;
    sigc::connection m_timerConnection;
	bool timeTrigger;

    void enableTracing();
    void disableTracing();

    void onTimer();

    void onDataMemoryAccess(S2EExecutionState *state,
                                   klee::ref<klee::Expr> address,
                                   klee::ref<klee::Expr> hostAddress,
                                   klee::ref<klee::Expr> value,
                                   bool isWrite, bool isIO);
	void onModuleTransition(
        S2EExecutionState *state,
        const ModuleDescriptor *prevModule,
        const ModuleDescriptor *currentModule);

    void onPrivilegeChange(
            S2EExecutionState *state,
            unsigned previous, unsigned current);
	/* this function is to collect all the overwritten memory address that
	 * export to library monitor and syscall monitor */
	void overWrittenAddressesCollection(S2EExecutionState *state, 
										uint64_t address, uint8_t flags);
public:
	//didn't consider the individual state, early version
	bool checkOverWrittenAddressesById(uint32_t stateId, uint64_t address,
        uint32_t &PtrCounts, uint32_t &OWcounts);

	//in considering the individual state
	bool checkOverWrittenAddressesByState(S2EExecutionState *state, uint64_t address,
        uint32_t &PtrCounts, uint32_t &OWcounts);

    bool checkOverWrittenAddressesById(uint32_t stateId, uint64_t address);

};


class LinuxMemoryTracerState: public PluginState{
private:
	typedef std::multimap<uint64_t, uint64_t> overWrittenAddressesState;

	overWrittenAddressesState m_overWrittenAddressesState;

	void overWrittenAddressesStateCollection(uint64_t timestamp, 
										uint64_t address, uint8_t flags);
public:
	virtual LinuxMemoryTracerState* clone()const ;
	static PluginState *factory(Plugin *p, S2EExecutionState *s);

	friend class LinuxMemoryTracer;
};

}
}

#endif
