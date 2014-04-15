#ifndef	_MEMORY_ANALYSIS_H
#define _MEMORY_ANALYSIS_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {
	
class MemoryAnalysis: public Plugin
{
	S2E_PLUGIN

public:
	MemoryAnalysis(S2E *s2e): Plugin(s2e) {	}
	//probably we need more customized signals in future
	sigc::signal<void, S2EExecutionState *, uint64_t> ;
	
	void initialize();
	void onModuleLoad(S2EExecutionState *state, uint64_t pc);
	void onMemoryWrite(S2EExecutionState *state, uint64_t pc);

};

}	//namespace plugins
}	//namespace s2e

//Plugin State for per state plugin information.
class MemoryAnalysisState: public PluginState
{

public:
    MemoryAnalysisState() {}

    ~MemoryAnalysisState() {}

    static PluginState * factory(Plugin*, S2EExecutionState*) {
        return new MemoryAnalysisState();
    }

   MemoryAnalysisState * clone() const {
        return new MemoryAnalysisState(*this);
    }

    void increment() { ++m_count; }
    int get() { return m_count; }

};
#endif

