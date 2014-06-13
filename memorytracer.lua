-- File: echo.lua
-- This file configured to work properly.
-- It can used to genrate Test cases and the fork is not anywhere in memory
s2e = {
  kleeArgs = {
  --"--use-concolic-execution=true",
  --"--use-batching-search=true",
  --"--flush-tbs-on-state-switch=false",
  "--state-shared-memory=true"
  }
}

plugins = {
  "BaseInstructions",
  "ExecutionTracer",
  "ModuleTracer",

  "RawMonitor",
  "ModuleExecutionDetector",

  --"FunctionMonitor",
  "MemoryTracer",
  "TestCaseGenerator",
  "TranslationBlockTracer",
  
  "CodeSelector",

  --"HostFiles",
  --"Annotation",
}

pluginsConfig = {}

pluginsConfig.MemoryTracer = {
	monitorMemory = true,
	monitorModules = true,
}

pluginsConfig.ModuleTracer = { }

pluginsConfig.TranslationBlockTracer = {

}

pluginsConfig.RawMonitor = {
  kernelStart = 0xC0000000
}

pluginsConfig.CodeSelector = {
	moduleIds = {"open_id"}
}

pluginsConfig.HostFiles = {
	baseDirs = { "/home/rui/s2e/myProg" }
}

pluginsConfig.TestCaseGenerator = {}

pluginsConfig.ModuleExecutionDetector = {
  open_id = {
    moduleName = "open",
    kernelMode = false,
  },
  trackAllModules = false,
  configureAllModules = false  
}

pluginsConfig.MemoryChecker = {}

--[[
pluginsConfig.RawMonitor = {
  kernelStart = 0xC0000000,
  echo_id = {
    delay = false,
	name = "echo",
	start = 0x0,
	size = 26136, 
	nativebase = 0x8048000,
	kernelmode = false
  }
}

pluginsConfig.CodeSelector = {
	moduleIds = {"echo_id"}
	--mduleIds = {"module1", "module2"}
	--module1 and module2 must be defined in
	--configuration script for ModuleExectionDetector plugin
}

--]]
 

