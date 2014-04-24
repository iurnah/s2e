/*
 * MemoryAnalyzer.cpp
 *
 *  Created on: April 13, 2014
 *      Author: Rui Han
 */

extern "C" {
#include <qemu-common.h>
}

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/InterruptMonitor.h>
#include <s2e/Plugins/MemoryAnalyzer/MemoryAnalyzer.h>

namespace s2e {
namespace Plugins {

S2E_DEFINE_PLUGIN(MemoryAnalyzer, "Memory Analyzer Plugin", "MemoryAnalyzer", "ExecutionTracer");

/*********************************************************************************
 *	initialize the shadown memory
 *********************************************************************************/
void MemoryAnalyzer::initialize(){

	init_shadow_memory();	

}

/*********************************************************************************
 *	update the memory shadow based on the loaded module.	
 *********************************************************************************/
void onModuleLoad(){

}

/*********************************************************************************
 *	
 *********************************************************************************/
void onMemoryWrite(){

}

/*********************************************************************************
 *	obtained the data type from system call parameters	
 *********************************************************************************/
void onSyscallTypeSink(){

}

/*********************************************************************************
 *	obtained the data type from system call parameters	
 *********************************************************************************/
void onLibcallTypeSink(){

}

/*********************************************************************************
 *	obtained the data type from system call parameters	
 *********************************************************************************/
void onInstructionTypeSink(){

}

} //namespace plugins 
} //namespace s2e
