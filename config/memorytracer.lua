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
  "BaseInstructions", 	--Enable S2E custom opcodes, enough to run the symbolic execution
  "RawMonitor", 	-- Track when the guest loads and unloads modules
  "ModuleExecutionDetector", -- Detect when execution enters the program of interest
  "CodeSelector", 	-- Restrict symbolic execution to the programs of interest
 
  "ExecutionTracer",
  "ModuleTracer",
  "MemoryTracer",
  "TranslationBlockTracer", 
  "StateSwitchTracer",
  "TestCaseGenerator",

  "X86FunctionMonitor",
  "LibraryCallMonitor",

  "HostFiles",
}


pluginsConfig = {}

pluginsConfig.MemoryTracer = { --same
	monitorMemory = true,
	monitorModules = true,
}

pluginsConfig.ModuleTracer = { }

pluginsConfig.TranslationBlockTracer = { }

pluginsConfig.RawMonitor = {
  kernelStart = 0xC0000000
}

pluginsConfig.CodeSelector = {
	moduleIds = { "prog2", "init_env.so" }
	-- as long match the ModuleExecutionDetector, it is ok.
}

pluginsConfig.HostFiles = {
	baseDirs = { "/home/rui/Research/SymbolicExecution/guest-prog/" }
}

pluginsConfig.TestCaseGenerator = {}

pluginsConfig.ModuleExecutionDetector = {
  init_env_id = { --have to remove the dot here and to process in the assignement process.
    moduleName = "init_env.so",
    kernelMode = false,
  },
  prog2 = {
    moduleName = "prog2",
    kernelMode = false,	
  },
  trackAllModules = true,
  configureAllModules = false  
}

pluginsConfig.X86FunctionMonitor = {

}

pluginsConfig.LibraryCallMonitor = {

}

pluginsConfig.MemoryChecker = {}

--[[
pluginsConfig = {}

pluginsConfig.RawMonitor = {
  kernelStart = 0xC0000000,
  prog1_id = {
        delay = false,-- False, RawMonitor considers the module to be loaded when S2E starts.
        name = "prog1", 
        start = 0x080483cc,	--From the guset objdump -h prog1 (start address 0x080483cc)
        size = 5147,		--From the guest stat prog1
        nativebase = 0x8048360, --.text, at <main>
        kernelmode = false
  }
}

pluginsConfig.ModuleExecutionDetector = {
  init_env = {
    moduleName = "init_env.so",
    kernelMode = false,
  },

  prog1_id = {
    moduleName = "prog1",
    kernelMode = false,	
  },

  trackAllModules = false,
  configureAllModules = false  
}

pluginsConfig.CodeSelector = {
	moduleIds = { "prog1_id" }
}

pluginsConfig.MemoryTracer = {
	monitorMemory = true,
	monitorModules = true,
}

pluginsConfig.ModuleTracer = { }

pluginsConfig.TranslationBlockTracer = {

}


pluginsConfig.HostFiles = {
	baseDirs = { "/home/rui/Research/SymbolicExecution/guest-prog/" }
}

pluginsConfig.TestCaseGenerator = {}



pluginsConfig.MemoryChecker = {}

]]--

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
