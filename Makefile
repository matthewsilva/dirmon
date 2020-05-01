all: dirmon
	g++ -lprocps -o dirmon FileMonitor.cpp DirectoryListAuditor.cpp

  clean: 
	$(RM) dirmon