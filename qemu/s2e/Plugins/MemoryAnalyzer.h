#ifndef	_MEMORY_ANALYZER_H
#define _MEMORY_ANALYZER_H

#include <string>
#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {
	
class MemoryAnalyzer: public Plugin
{
	S2E_PLUGIN
private:
	ExecutionTracer *m_tracer;
	ModuleExecutionDetector *m_executionDetector;

	bool m_monitorModules;
	bool m_memoryMonitor;
	bool m_stackMonitor;
	bool m_heapMonitor;

	sigc::connection m_DataMemoryMonitor;

public:
	MemoryAnalyzer(S2E *s2e): Plugin(s2e) {	}
	//probably we need more customized signals in future
	//sigc::signal<void, S2EExecutionState *, uint64_t> ;
	
	void initialize();
	void enableTracing();
	void onModuleTransition(S2EExecutionState *state,
							const ModuleDescriptor *prevModule,
							const ModuleDescriptor *nextModule);
	void onDataMemoryAccess(S2EExecutionState *state, 
							klee::ref<klee::Expr> address,
							klee::ref<klee::Expr> hostAddress,
							klee::ref<klee::Expr> values,
							bool isWrite, bool isIO);

	void onMemoryWrite(S2EExecutionState *state, uint64_t pc);

	void traceDataMemoryAccess(S2EExecutionState *state,
								klee::ref<klee::Expr> &address,
								klee::ref<klee::Expr> &hostAddress,
								klee::ref<klee::Expr> &value,
								bool isWrite, bool isIO);

};

}	//namespace plugins
}	//namespace s2e

/*
//Plugin State for per state plugin information.
class MemoryAnalyzerState: public PluginState
{

public:
    MemoryAnalyzerState() {}

    ~MemoryAnalyzerState() {}

    static PluginState * factory(Plugin*, S2EExecutionState*) {
        return new MemoryAnalyzerState();
    }

   MemoryAnalyzerState * clone() const {
        return new MemoryAnalyzerState(*this);
    }

};
*/
#endif

