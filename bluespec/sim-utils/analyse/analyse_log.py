from __future__ import annotations

from pathlib import Path
from typing import Tuple, List
from collections import defaultdict
# import matplotlib.pyplot as plt
import numpy as np
from dataclasses import dataclass
import argparse

class Capability:
    def __init__(self, line, parent):
        #print(line)
        _, boundsOffset, _, boundsLength, _, boundsVirtualBase, _, capPerms   = line.split()
        self.boundsOffset = int(boundsOffset, 16)
        self.boundsLength = int(boundsLength, 16)
        self.boundsVirtBase = int(boundsVirtualBase, 16)
        self.capPerms = int(capPerms, 16)
        self.parent = parent
        parent.child = self

    def capKey(self):
        return (self.boundsVirtBase, self.boundsLength)
    
    def __eq__(self, other):
        return self.boundsOffset == other.boundsOffset and self.boundsLength == other.boundsLength and self.boundsVirtBase == other.boundsVirtBase and self.capPerms == other.capPerms

    def __hash__(self):
        return hash((self.boundsOffset, self.boundsLength, self.boundsVirtBase, self.capPerms))
    
    def __repr__(self):
        return f"Cap virtBase {self.boundsVirtBase} length {self.boundsLength} offset {self.boundsOffset}"

class ReportAccessLog:
    def __init__(self, line, index):
        #44200 Prefetcher logReportAccess level 1 addr 00000000c0007648 pcHash c0000260 hitMiss 1 boundsOffset 0000000000000008 boundsLength 0000000000002f30 boundsVirtBase 00000000c0007640 capPerms 0000000000001111000111111010111

        #print(line.split())
        clock_time,_, _, _, addr, _, pcHash, _, isMiss, _, boundsOffset, _, boundsLength, _, boundsVirtualBase, _, capPerms, _, op   = line.split()
        self.clock_time = int(clock_time)/10
        self.addr = int(addr, 16)
        self.pcHash = int(pcHash, 16)
        self.isMiss = int(isMiss)
        self.op = op
        self.cap = Capability("boundsOffset"+line.partition("op")[0].partition("boundsOffset")[2], self)

        self.index = index
    
class ReportDataArrivalCap:
    def __init__(self, line, parent):
        pre, _, cap = line.partition("boundsOffset")
        _, _, _, _, index, _, tag, _, addr = pre.split()
        self.index = int(index)
        self.tag = bool(int(tag))
        self.addr = int(addr, 16)
        if self.tag:
            self.cap = Capability("boundsOffset"+cap, parent)
        self.parent = parent
        parent.child = self

class ReportDataArrival:
    def __init__(self, line, index):
        clock_time,_, _, _, requestAddr, _, pcHash, _, wasMiss, _, wasPrefetch, _, boundsOffset, _, boundsLength, _, boundsVirtualBase, _, capPerms, _, op  = line.split()
        self.clock_time = int(clock_time)/10
        self.requestAddr = int(requestAddr, 16)
        self.pcHash = int(pcHash, 16)
        self.wasMiss = int(wasMiss)
        self.wasPrefetch = int(wasPrefetch)

        #print(line)
        self.requestCap = Capability("boundsOffset"+line.partition("op")[0].partition("boundsOffset")[2], self)
        self.capabilites: List[ReportDataArrivalCap] = []

        self.sel_capability = None

        self.index = index

    def add_capability(self, line, parent_data_arrivals):
        capability = ReportDataArrivalCap(line, self)
        if capability.tag:
            self.capabilites.append(capability)
            parent_data_arrivals[capability.cap.capKey()] = capability.cap 

        return capability

    def add_sel_capability(self, line):
        capability = ReportDataArrivalCap(line, self)
        if capability.tag:
            self.sel_capability = capability 

        return capability

class NextPrefetchAddr:
    def __init__(self, line):
        clock_time,_, _, addr = line.split()
        self.clock_time = int(clock_time)/10
        self.addr = int(addr, 16)

class TlbResponse:
    def __init__(self, line):
        self.clock_time = int(line.split()[0])/10
        self.paddr = int(line.split()[8].strip(",").strip("'h"), 16)

@dataclass
class PredictionResponseMatch:
    clock_time: str
    predIdxTag: int
    parentOffset: int
    childOffset: int
    confidence: int
    virtBase: int

@dataclass
class BackwardsHit:
    tag: int
    parentVirtBase: int
    parentOffset: int
    childOffset: int
    clock_time: str

@dataclass
class BackwardsAddition:
    parentVirtBase:int
    parentOffset: int
    idxTag: int
    clock_time: str

@dataclass
class TimelinessRdResp:
    valid: bool
    idx: int
    tag: int
    pcHash: int
    clock_time: str
    replacementWay: int

@dataclass
class PredictionReplacement:
    clock_time: str
    idx: int
    tag: int
    newParentOffset: int
    newChildOffset: int
    oldParentOffset: int
    oldChildOffset: int

@dataclass 
class TimelinessReplacement:
    clock_time: str
    repResp: int
    idx: int
    tag: int
    pcHash: int

@dataclass
class PredictionDecrease:
    clock_time: str
    idx: int
    tag: int
    oldConfidence: int
    oldParentOffset: int
    oldChildOffset: int

@dataclass
class PredictionMatchUpdate:
    clock_time: str
    idx: int
    tag: int
    oldConfidence: int

def parse_log(input_file, ignore_first_n_instr, ignore_last_n_instr) -> Tuple[List[ReportAccessLog], List[ReportDataArrival], List[ReportAccessLog]]:
    total_order_events = []
    recent_misses = set()
    parent_access = {} #(cap_virtual_base, cap_size, most recent ReportAccessLog)
    parent_data_arrivals = {} #(cap_virtual_base, cap_size, most recent ReportAccessLog)
    accesses = []
    data_arrivals = []
    access_misses = []

    missess_not_prefetcher = 0

    access_index = 0
    data_arrival_index = 0
    
    instruction_count = 0
    instruction_start_time = 0
    instruction_end_time = 0

    prefetch_hit_count = 0
    prefetch_total_count = 0
    prefetch_total_miss_count = 0

    with open(input_file, "r") as fp:
        while True:
            line = fp.readline()
            if not line:
                break

            if "logReportAccess" in line:
                reportAccess = ReportAccessLog(line, access_index)
                total_order_events.append(reportAccess)

                access_index += 1

                if reportAccess.isMiss:
                    recent_misses.add(reportAccess.addr)
                    access_misses.append(reportAccess)
                elif reportAccess.addr in recent_misses:
                    #Skip first hit access after miss
                    recent_misses.remove(reportAccess.addr)
                    continue

                accesses.append(reportAccess)
                parent_access[reportAccess.cap.capKey()] = reportAccess.cap

                if reportAccess.cap.capKey() in parent_data_arrivals:
                    parent = parent_data_arrivals[reportAccess.cap.capKey()]
                    reportAccess.parent = parent
                    parent.child = reportAccess
                    #parent.child = reportAccess
                    #print("found parent")

                # if reportAccess.cap.boundsLength == 40000:
                #         print("40000 arrival")
                #         print(reportAccess.cap.capKey())
                #print(reportAccess.cap.boundsLength)
            
            elif "logReportDataArrival" in line:
                data_arrival = ReportDataArrival(line, data_arrival_index)
                total_order_events.append(data_arrival)
                data_arrival_index += 1 

                data_arrival.add_capability(fp.readline(), parent_data_arrivals)
                data_arrival.add_capability(fp.readline(), parent_data_arrivals)
                data_arrival.add_capability(fp.readline(), parent_data_arrivals)
                data_arrival.add_capability(fp.readline(), parent_data_arrivals)

                data_arrival.add_sel_capability(fp.readline())

                data_arrivals.append(data_arrival)

                if data_arrival.requestCap.capKey() in parent_access:
                    # if data_arrival.requestCap.boundsLength == 40000:
                    #     print("40000 arrival in arrival")
                    parent = parent_access[data_arrival.requestCap.capKey()]
                    data_arrival.parent = parent
                    parent.child = data_arrival
                    #parent.child = data_arrival
                    #print("found parent2")

                # if data_arrival.requestCap.boundsLength == 40000:
                #     print(data_arrival.requestCap.capKey())

                if ignore_first_n_instr <= instruction_count and instruction_count <= ignore_last_n_instr: 
                    if data_arrival.wasMiss and not data_arrival.wasPrefetch:
                        missess_not_prefetcher += 1

                    if data_arrival.wasPrefetch:
                        prefetch_total_count += 1

                    if data_arrival.wasPrefetch and data_arrival.wasMiss:
                        prefetch_total_miss_count += 1
                    
            elif "getNextPrefetchAddr" in line:
                getNextPrefetchAddr = NextPrefetchAddr(line)
                total_order_events.append(getNextPrefetchAddr)

            elif "got TLB response" in line:
                tlbResponse = TlbResponse(line)
                total_order_events.append(tlbResponse)

            elif "processPredictionResponse tag match and valid offset" in line:
                clock_time, _, _, _, _, _, _, _, _, predIdxTag, _, parentOffset, _, childOffset, _, confidence, _, virtBase = line.split()
                predIdxTag = int(predIdxTag, 16)
                parentOffset = int(parentOffset, 16)
                childOffset = int(childOffset, 16)
                confidence = int(confidence, 16)
                virtBase = int(virtBase, 16)

                predResponse = PredictionResponseMatch(clock_time, predIdxTag, parentOffset, childOffset, confidence, virtBase)
                total_order_events.append(predResponse)

            elif "backwards table hit" in line:
                clock_time, _, _, _, _, _, tag, _, parentVirtBase, _, parentOffset, _, childOffset = line.split()
                tag = int(tag, 16)
                parentVirtBase = int(parentVirtBase, 16)
                parentOffset = int(parentOffset, 16)
                childOffset = int(childOffset, 16)
                backwardsHit = BackwardsHit(tag, parentVirtBase, parentOffset, childOffset, clock_time)
                total_order_events.append(backwardsHit)

            elif "added to backwards table" in line:
                clock_time, _, _, _, _, _, _, _, parentVirtBase, _, parentOffset, _, idx, _, childTag = line.split()
                parentVirtBase = int(parentVirtBase, 16)
                parentOffset = int(parentOffset, 16)

                idxTag = int(childTag + idx, 16)
                backwardsAddition = BackwardsAddition(parentVirtBase, parentOffset, idxTag, clock_time)

                total_order_events.append(backwardsAddition) 

            elif "timeliness table rdResp" in line:
                clock_time, _, _, _, _, _, valid, _, idx, _, tag, _, pcHash, _, repWay, _, _ = line.partition("fshow")[0].split()
                valid = int(valid)
                idx = int(idx, 16)
                tag = int(tag, 16)
                pcHash = int(pcHash, 16)
                timelinessRdResp = TimelinessRdResp(valid, idx, tag, pcHash, clock_time, repWay)
                total_order_events.append(timelinessRdResp)
            
            elif "processPredictionReplacementRd replacement" in line:
                clock_time, _, _, _, _, idx, _, tag, _, newParentOffset, _, newChildOffset, _, oldParentOffset, _, oldChildOffset = line.split()
                idx = int(idx, 16)
                tag = int(tag, 16)
                newParentOffset = int(newParentOffset, 16)
                newChildOffset = int(newChildOffset, 16)
                oldParentOffset = int(oldParentOffset, 16)
                oldChildOffset = int(oldChildOffset, 16)
                predictionReplacement = PredictionReplacement(clock_time, idx, tag, newParentOffset, newChildOffset, oldParentOffset, oldChildOffset)
                total_order_events.append(predictionReplacement)

            elif "processPredictionReplacementRd decrease" in line:
                clock_time, _, _, _, _, _, oldConfidence, _, idx, _, tag, _, oldParentOffset, _, oldChildOffset = line.split()
                idx = int(idx, 16)
                tag = int(tag, 16)
                oldConfidence = int(oldConfidence, 16)
                oldParentOffset = int(oldParentOffset, 16)
                oldChildOffset = int(oldChildOffset, 16)

                predictionDecrease = PredictionDecrease(clock_time, idx, tag, oldConfidence, oldParentOffset, oldChildOffset)
                total_order_events.append(predictionDecrease)

            elif "table miss" in line:
                for i in range(len(total_order_events)-1, 0, -1):
                    if isinstance(total_order_events[i], TimelinessRdResp):
                        total_order_events.pop(i)
                        break

            elif "timeliness replacement" in line:
                clock_time, _, _, _, _, repRepl, _, _, _, idx, _, tag, _, pcHash = line.split()
                repRepl = int(repRepl)
                idx = int(idx, 16)
                tag = int(tag, 16)
                pcHash = int(pcHash, 16)
                timelinessRepl = TimelinessReplacement(clock_time, repRepl, idx, tag, pcHash)
                total_order_events.append(timelinessRepl)

            elif "processPredictionReplacementRd match" in line:
                clock_time, _, _, _, _, _, oldConfidence, _, idx, _, tag = line.split()
                oldConfidence = int(oldConfidence, 16)
                idx = int(idx, 16)
                tag = int(tag, 16)
                predictionMatchUpdate = PredictionMatchUpdate(clock_time, idx, tag, oldConfidence)
                total_order_events.append(predictionMatchUpdate)

            elif "L1 demand hit on prefetched cache line" in line:
                if ignore_first_n_instr <= instruction_count and instruction_count <= ignore_last_n_instr: 
                    prefetch_hit_count += 1
        
            if "RVFI Order" in line:
                instruction_count += 1
                clock_time = int(line.split()[0].strip(":"))/10
                if instruction_count == ignore_first_n_instr:
                    instruction_start_time = clock_time
                if instruction_count == ignore_last_n_instr:
                    instruction_end_time = clock_time
                    break

    print(f"access {len(accesses)} misses {len(access_misses)}")
    print(f"IPC {(ignore_last_n_instr - ignore_first_n_instr)/ (instruction_end_time - instruction_start_time)}")
    print(f"Instruction count {instruction_count} num of cycles {instruction_end_time - instruction_start_time}")
    ipc = {(ignore_last_n_instr - ignore_first_n_instr)/ (instruction_end_time - instruction_start_time)}
    return ipc, prefetch_hit_count, missess_not_prefetcher, prefetch_total_count, prefetch_total_miss_count


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Analyse log from CHERI-BGAS simulation')

    parser.add_argument('-i', "--input",)
    parser.add_argument('-u', "--upperbound", type=int)

    args = parser.parse_args()
    input_file_with_prefetcher = Path("/local/scratch-3/tm746/simulations_v2")/"with-prefetcher"/args.input/"sim_0.0"/"sim_stdout"
    input_file_logging_prefetcher = Path("/local/scratch-3/tm746/simulations_v2")/"logging-prefetcher"/args.input/"sim_0.0"/"sim_stdout"
    input_file_without_prefetcher = Path("/local/scratch-3/tm746/simulations_v2")/"without-prefetcher"/args.input/"sim_0.0"/"sim_stdout"

    ipc_with_prefetcher, prefetch_hit_count_with, missess_not_prefetcher_with, prefetch_total_count, prefetch_total_miss_count = parse_log(input_file_with_prefetcher, 100000, args.upperbound)
    ipc_without_prefetcher, _, missess_not_prefetcher_without, _, _ = parse_log(input_file_without_prefetcher, 100000, args.upperbound)
    ipc_logging_prefetcher, _, _, _, _ = parse_log(input_file_logging_prefetcher, 100000, args.upperbound)
    print(f"IPC with prefetcher {ipc_with_prefetcher}")
    print(f"IPC without prefetcher {ipc_without_prefetcher}")
    print(f"IPC logging prefetcher {ipc_logging_prefetcher}")
    print(f"Coverage {prefetch_hit_count_with/missess_not_prefetcher_without}")
    print(f"Accuracy {prefetch_hit_count_with/prefetch_total_count}")
    print(f"Accuracy (only prefetch misses) {prefetch_hit_count_with/prefetch_total_miss_count}")
