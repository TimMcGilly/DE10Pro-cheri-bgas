import argparse
from pathlib import Path
from typing import Tuple

# cap_size_map = dict[tuple[int, int], int] #(cap_size_hit, cap_size_miss) count
# offset_map = dict[tuple[int, int], int] #(offset_hit, offset_miss) count
# cap_size_offset_map = dict[tuple]
class Capability:
    def __init__(self, line, parent):
        #print(line)
        _, boundsOffset, _, boundsLength, _, boundsVirtualBase, _, capPerms   = line.split()
        self.boundsOffset = int(boundsOffset, 16)
        self.boundsLength = int(boundsLength, 16)
        self.boundsVirtBase = int(boundsVirtualBase, 16)
        self.capPerms = int(capPerms, 2)
        self.parent = parent

    def capKey(self):
        return (self.boundsVirtBase, self.boundsLength)

class ReportAccessLog:
    def __init__(self, line):
        #44200 Prefetcher logReportAccess level 1 addr 00000000c0007648 pcHash c0000260 hitMiss 1 boundsOffset 0000000000000008 boundsLength 0000000000002f30 boundsVirtBase 00000000c0007640 capPerms 0000000000001111000111111010111

        #print(line.split())
        clock_time,_, _, _, level, _, addr, _, pcHash, _, isMiss, _, boundsOffset, _, boundsLength, _, boundsVirtualBase, _, capPerms   = line.split()
        self.clock_time = int(clock_time)
        self.level = int(level)
        self.addr = int(addr, 16)
        self.pcHash = int(pcHash, 16)
        self.isMiss = int(isMiss)

        
        self.cap = Capability("boundsOffset"+line.partition("boundsOffset")[2], self)
        # self.boundsOffset = int(boundsOffset, 16)
        # self.boundsLength = int(boundsLength, 16)
        # self.boundsVirtBase = int(boundsVirtualBase, 16)
        # self.capPerms = int(capPerms, 2)
    
    @staticmethod
    def is_match(line):
        return "logReportAccess" in line
    
class ReportDataArrival:
    def __init__(self, line):
#Prefetcher logReportDataArrival level %d requestAddr %h pcHash %h wasMiss %b wasPrefetch %b boundsOffset %h boundsLength %h boundsVirtBase %h capPerms %b"        print(line.split())
        clock_time,_, _, _, level, _, requestAddr, _, pcHash, _, wasMiss, _, wasPrefetch, _, boundsOffset, _, boundsLength, _, boundsVirtualBase, _, capPerms   = line.split()
        self.clock_time = int(clock_time)
        self.level = int(level)
        self.requestAddr = int(requestAddr, 16)
        self.pcHash = int(pcHash, 16)
        self.wasMiss = int(wasMiss)
        self.wasPrefetch = int(wasPrefetch)
        self.requestCap = Capability("boundsOffset"+line.partition("boundsOffset")[2], self)
    
    @staticmethod
    def is_match(line):
        return "logReportDataArrival" in line


def parse_log(input_file):
    recent_misses = set()
    parent_access = {} #(cap_virtual_base, cap_size, most recent ReportAccessLog)
    parent_dataarrivals = {} #(cap_virtual_base, cap_size, most recent ReportAccessLog)
    accesses = []
    dataArrivals = []
    access_misses = []


    with open(input_file, "r") as fp:
        while True:
            line = fp.readline()
            if not line:
                break

            if "logReportAccess" in line:
                reportAccess = ReportAccessLog(line)

                if reportAccess.isMiss:
                    recent_misses.add(reportAccess.addr)
                    access_misses.append(reportAccess)
                elif reportAccess.addr in recent_misses:
                    #Skip first hit access after miss
                    recent_misses.remove(reportAccess.addr)
                    continue

                accesses.append(reportAccess)
                parent_access[reportAccess.cap.capKey()] = reportAccess.cap

                if reportAccess.cap.capKey() in parent_dataarrivals:
                    parent = parent_dataarrivals[reportAccess.cap.capKey()]
                    reportAccess.parent = parent
                    #parent.child = reportAccess
                    #print("found parent")
            
            elif "logReportDataArrival" in line:
                dataArrival = ReportDataArrival(line)
                dataArrival.cap1 = Capability("boundsOffset"+fp.readline().partition("boundsOffset")[2], dataArrival)
                dataArrival.cap2 = Capability("boundsOffset"+fp.readline().partition("boundsOffset")[2], dataArrival)
                dataArrival.cap3 = Capability("boundsOffset"+fp.readline().partition("boundsOffset")[2], dataArrival)
                dataArrival.cap4 = Capability("boundsOffset"+fp.readline().partition("boundsOffset")[2], dataArrival)

                dataArrivals.append(dataArrival)
                parent_dataarrivals[dataArrival.cap1.capKey()] = dataArrival.cap1
                parent_dataarrivals[dataArrival.cap2.capKey()] = dataArrival.cap2
                parent_dataarrivals[dataArrival.cap3.capKey()] = dataArrival.cap3
                parent_dataarrivals[dataArrival.cap4.capKey()] = dataArrival.cap4

                if dataArrival.requestCap.capKey() in parent_access:
                    parent = parent_access[dataArrival.requestCap.capKey()]
                    dataArrival.parent = parent
                    #parent.child = dataArrival
                    #print("found parent2")


    print(f"access {len(accesses)} misses {len(access_misses)}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Analyse log from CHERI-BGAS simulation')

    parser.add_argument('-i', "--input",)    

    args = parser.parse_args()
    input_file = Path(args.input) / "sim_0.0" / "sim_stdout"
    
    parse_log(input_file)
