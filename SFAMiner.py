import multiprocessing
from multiprocessing.dummy import Pool as ThreadPool
from functools import partial
import os
from argparse import ArgumentParser
import shutil
import sqlite3
import subprocess
import time
from bitarray import bitarray
import graphviz
import itertools
import random
import copy
import re
from datetime import datetime
from pathlib import Path


MIN_SUPPORT = 10
# MIN_SUPPORT = 800
MIN_CONFIDENCE = 0.5
SFA_VOTE = 0.9
PROCESSOR = 24
processTotal = 0
processCount = 0
locationTableID = 0
itemsTableID = 0
start = 0
TIMEOUT = 600

condPattern = r'(.+)\((.+)\) (.+) (.+)'
returnPattern = r'RETURN (.+)\((.+)\)'

debugAPI = {'openssl': {'test_false', 'ERR_print_errors', 'test_str_eq', 'test_ptr_eq', 'test_uint64_t_eq', 'test_int_le', 'ERR_peek_error', 'test_get_argument', 'ERR_reason_error_string', 'test_BN_eq', 'SSL_get_error', 'ERR_GET_REASON', 'BIO_test_flags', 'test_ptr_null', 'test_int_ge', 'ERR_peek_last_error', 'ERR_GET_LIB', 'ERR_set_error', 'test_int_ne', 'test_ptr_ne', 'strchr', 'strncmp', 'OPENSSL_strcasecmp', 'BN_is_negative', 'CRYPTO_memcmp', 'BN_is_zero', 'bcmp', 'EVP_PKEY_CTX_free', 'BN_cmp', 'EVP_CIPHER_CTX_is_encrypting', 'TLS_server_method'}, 'linux': {'__dynamic_dev_dbg', '_dev_err', 'perf_trace_run_bpf_submit', 'bpf_prog_array_valid', 'perf_fetch_caller_regs', 'strnlen', 'trace_event_printf', 'trace_handle_return', 'strcmp', 'IS_ERR_OR_NULL', 'bcmp', 'refcount_dec_and_test', 'dev_driver_string', '__refcount_dec_and_test'}}

predicateMap = {'FCMP_FALSE': 0, 'FCMP_OEQ' : 1, 'FCMP_OGT': 2, 'FCMP_OGE': 3, 'FCMP_OLT': 4,'FCMP_OLE': 5, 'FCMP_ONE': 6, 'FCMP_ORD': 7, 'FCMP_UNO': 8, 'FCMP_UEQ': 9, 'FCMP_UGT': 10, 'FCMP_UGE': 11, 'FCMP_ULT': 12, 'FCMP_ULE': 13, 'FCMP_UNE': 14, 'FCMP_TRUE': 15, 'BAD_FCMP_PREDICATE': 16, 'ICMP_EQ': 32, 'ICMP_NE': 33, 'ICMP_UGT': 34,'ICMP_UGE': 35, 'ICMP_ULT': 36, 'ICMP_ULE': 37, 'ICMP_SGT': 38, 'ICMP_SGE': 39, 'ICMP_SLT': 40, 'ICMP_SLE': 41, 'BAD_ICMP_PREDICATE': 42}

clusterAPI = {'mutex_lock_interruptible_nested': 'mutex_lock_nested', 'mutex_lock_killable_nested': 'mutex_lock_nested', 'mutex_lock_io_nested': 'mutex_lock_nested', '_atomic_dec_and_lock_irqsave': '_raw_spin_lock_irqsave', 'kfree_sensitive': 'kfree'}

debugPattern = {'openssl': {'BIO_printf', 'ERR_print_errors', 'TLS_server_method'}, 'linux': {'__dynamic_dev_dbg', '_dev_err', 'perf_trace_run_bpf_submit', 'PTR_ERR', 'dev_set_drvdata', 'IS_ERR'}}

notBugAPIPatterns = {'linux': {'unlock', 'print', 'debug', 'set_drvdata', 'list_del', '__fortify_panic', 'write', 'read', 'disable', 'free', 'dev_err', 'cmp', 'put', 'unmap', 'destroy', 'release', 'dbg', 'remove', 'finish', 'wreg', 'time', 'info', 'err', 'update', 'warn', 'format', 'assert', 'trim', 'reserve', 'exit', 'unregister', 'set', 'elapsed', 'cancel', 'cleanup', 'abort', 'get_drvdata', 'off', 'dump', 'close', 'alert', 'shutdown', 'done', 'unprepare', 'detach', 'unload'}, 'openssl': {'test_', 'free'}}
notBugAPIs = {'linux': {'up', 'regcache_mark_dirty', 'cpu_online', 'PTR_ERR_OR_ZERO', 'skb_headroom', 'regcache_cache_only', 'sized_strscpy', 'irqd_to_hwirq', 'rdev_get_id', 'spi_sync', 'spi_get_chipselect', 'get_unaligned_le64', 'die', 'cpumask_next', 'device_for_each_child', 'phy_disconnect', '__fswab64', 'rcu_is_watching', '___ratelimit', 'lockdep_init_map', '__init_work', '__raw_spin_lock_init', 'list_add_tail', 'prepare_to_wait_event', '_copy_from_user', '_copy_to_user', 
'trace_event_buffer_commit', 'capable', 'is_vmalloc_addr', 'of_find_property', '__devm_regmap_init_i2c', 'usb_submit_urb', 'sscanf', 'pci_enable_device', 'usb_control_msg', 'try_module_get', 'xa_find', 'kstrtoull', 'kstrtouint', 'skb_dequeue'}, 'openssl': {'strcmp', 'TLS_client_method', 'OPENSSL_sk_value', 'OPENSSL_sk_num', 'BN_is_odd', 'BN_ucmp', 'strstr', 'ossl_prov_is_running', 'OPENSSL_sk_push', 'ossl_cipher_generic_initkey', 'WPACKET_put_bytes__', 'ERR_get_error', 'SSL_CTX_ctrl', 'OPENSSL_sk_find', 'X509_up_ref', 'SSL_session_reused', 'RAND_bytes', 'SSL_CTX_set_cipher_list', 'BN_set_word', 'EVP_DigestFinal_ex', 'EVP_DigestUpdate', 'BN_CTX_get', 'ENGINE_ctrl_cmd_string', 'SSL_CTX_set_ciphersuites', 'SSL_get_ex_data_X509_STORE_CTX_idx', 'memcmp', 'X509_STORE_CTX_set_error', 'setsockopt', 'X509_NAME_oneline', 'BIO_set_callback_arg', 'BIO_meth_set_ctrl', 'getenv', 'ENGINE_ctrl_cmd', 'BIO_meth_set_write', 'EVP_EncryptInit_ex', 'HMAC_Init_ex', 'ENGINE_set_default', 'EVP_get_digestbyname', 'opt_next', 'SSL_CTX_set_ciphersuites', 'memcmp'}, 'ffmpeg': {'av_index_search_timestamp', 'ff_add_format', 'ff_vlc_init_sparse', 'av_expr_parse_and_eval'}}
notBugFunctions = {'linux': {'devm_kmalloc_array', 'devm_krealloc', 'devm_kzalloc', 'kmalloc_array', 'kzalloc', 'kcalloc', 'lock_is_held', 'copy_from_sockptr_offset', '__dev_alloc_pages', '__skb_queue_before', 'acpi_dev_name', 'alloc_cpumask_var', 'alloc_skb'}}

# linuxAPI = {'clk_enable', 'alloc_workqueue', 'kzalloc', 'platform_get_irq', 'kcalloc', 'dma_set_mask_and_coherent', 'kmemdup', 'devm_kcalloc', '__platform_driver_register', 'kmem_cache_alloc_trace', 'ioremap', 'platform_get_resource', 'request_threaded_irq', 'dma_set_coherent_mask', 'dma_alloc_coherent', 'device_create_file', 'devm_request_threaded_irq', 'devm_kzalloc', 'devm_clk_get', 'dma_map_single_attrs', 'devm_ioremap', 'nla_memdup', '_usecs_to_jiffies', 'kstrdup', 'vzalloc', 'mipi_dsi_driver_register_full', 'alloc_pages', 'snd_soc_dai_stream_valid', 'devm_regulator_get', 'kvmalloc_array', 'coda_iram_alloc', 'mc13xxx_irq_request', 'of_get_child_by_name', 'mtk_btcvsd_snd_write', 'pci_enable_device', 'nla_put_u32', '__kmalloc', 'dma_set_mask', 'skb_clone', 'kmalloc_array', 'device_property_read_u32_array', 'ida_alloc_range', '__devm_regmap_init_mmio_clk', 'idr_alloc', '__alloc_percpu', 'i2c_register_driver', '_copy_from_user'}

# linuxTimeoutAPI = {'__devm_regmap_init_mmio_clk', 'devm_ioremap', 'pfkey_broadcast'}


def checkFeasibility(existedPredicates, predicate):
  if predicate == 0 and 15 in existedPredicates or predicate == 15 and 0 in existedPredicates:
    return False
  elif predicate == 1 and 6 in existedPredicates or predicate == 6 and 1 in existedPredicates:
    return False
  elif predicate == 2 and 5 in existedPredicates or predicate == 5 and 2 in existedPredicates:
    return False
  elif predicate == 3 and 4 in existedPredicates or predicate == 4 and 3 in existedPredicates:
    return False
  elif predicate == 7 and 8 in existedPredicates or predicate == 8 and 7 in existedPredicates:
    return False
  elif predicate == 9 and 14 in existedPredicates or predicate == 14 and 9 in existedPredicates:
    return False
  elif predicate == 10 and 13 in existedPredicates or predicate == 13 and 10 in existedPredicates:
    return False
  elif predicate == 11 and 12 in existedPredicates or predicate == 12 and 11 in existedPredicates:
    return False
  elif predicate == 32 and 33 in existedPredicates or predicate == 33 and 32 in existedPredicates:
    return False
  elif predicate == 34 and 37 in existedPredicates or predicate == 37 and 34 in existedPredicates:
    return False
  elif predicate == 35 and 36 in existedPredicates or predicate == 36 and 35 in existedPredicates:
    return False
  elif predicate == 38 and 41 in existedPredicates or predicate == 41 and 38 in existedPredicates:
    return False
  elif predicate == 39 and 40 in existedPredicates or predicate == 40 and 39 in existedPredicates:
    return False
  return True
  

def isOppositeCondition(prevEdge, currEdge):
  prevEdgeValue = itemMapSet[prevEdge]
  currEdgeValue = itemMapSet[currEdge]
  prevEdgeVars = re.match(condPattern, prevEdgeValue, re.M | re.I)
  currEdgeVars = re.match(condPattern, currEdgeValue, re.M | re.I)
  if prevEdgeVars and currEdgeVars:
    if prevEdgeVars.group(1) == currEdgeVars.group(1) and prevEdgeVars.group(2) == currEdgeVars.group(2) and prevEdgeVars.group(4) == currEdgeVars.group(4):
      prevPredicate = predicateMap[prevEdgeVars.group(3)]
      currPredicate = predicateMap[currEdgeVars.group(3)]
      if prevPredicate == 0 and currPredicate == 15 or prevPredicate == 15 and currPredicate == 0:
        return True
      elif prevPredicate == 1 and currPredicate == 6 or prevPredicate == 6 and currPredicate == 1:
        return True
      elif prevPredicate == 2 and currPredicate == 5 or prevPredicate == 5 and currPredicate == 2:
        return True
      elif prevPredicate == 3 and currPredicate == 4 or prevPredicate == 4 and currPredicate == 3:
        return True
      elif prevPredicate == 7 and currPredicate == 8 or prevPredicate == 8 and currPredicate == 7:
        return True
      elif prevPredicate == 9 and currPredicate == 14 or prevPredicate == 14 and currPredicate == 9:
        return True
      elif prevPredicate == 10 and currPredicate == 13 or prevPredicate == 13 and currPredicate == 10:
        return True
      elif prevPredicate == 11 and currPredicate == 12 or prevPredicate == 12 and currPredicate == 11:
        return True
      elif prevPredicate == 32 and currPredicate == 33 or prevPredicate == 33 and currPredicate == 32:
        return True
      elif prevPredicate == 34 and currPredicate == 37 or prevPredicate == 37 and currPredicate == 34:
        return True
      elif prevPredicate == 35 and currPredicate == 36 or prevPredicate == 36 and currPredicate == 35:
        return True
      elif prevPredicate == 38 and currPredicate == 41 or prevPredicate == 41 and currPredicate == 38:
        return True
      elif prevPredicate == 39 and currPredicate == 40 or prevPredicate == 40 and currPredicate == 39:
        return True
  return False


def isSub(a, b):
  for item in a:
    if item not in b:
      return False
  return True


def getUsedTime(startTime):
  usedTime = time.time() - startTime
  if usedTime > TIMEOUT:
    return usedTime
  return 0


# def queryIDSet(IDSet, table):
#   result = []
#   for ID in IDSet:
#     if table == 'Items':
#       cur.execute('select Value from Items where ID = ?', (ID, ))
#       result.append(cur.fetchone()[0])
#     elif table == 'Locations':
#       cur.execute('select File, Function from Locations where ID = ?', (ID, ))
#       result.append(cur.fetchone())
#   return result


def bitArrayStr2IDSet(bitArrayStr):
  IDSet = set(i for i, x in enumerate(bitArrayStr) if x == '1')
  return IDSet


def IDSet2BitArray(IDSet, length):
  bitArray = bitarray(length)
  bitArray.setall(0)
  for ID in IDSet:
    bitArray[int(ID)] = 1
  return bitArray


# 守护进程
def abortable_worker(func, *args, **kwargs):
    timeout = kwargs.get('timeout', None)
    p = ThreadPool(1)
    res = p.apply_async(func, args=args)
    try:
        out = res.get(timeout)  # Wait timeout seconds for func to complete.
        # print(out)
        return out
    except multiprocessing.TimeoutError:
        print('{} timeout'.format(args[0]))
        return (args[0], 444)

# 回调函数
def collectMyResult(result = None):
    # print('Got result {}'.format(result))
    global processCount, processTotal, start
    processCount += 1 #全局变量统计任务执行进度
    end = time.time()
    print('\rExecution time:', str(int(end - start)), 's, progress finished: {}/{}'.format(processCount, processTotal), end ='')
    # if result:
    #   cur.execute('insert into opensslFSM(API) values(?)', (result, ))


# 递归有很大的隐患，目前的编译器都做不到
# def findSameNodes(node, nodePairs, visitedNodes):
#   if node[0] in visitedNodes and node[1] in visitedNodes[node[0]]:
#     return []
#   if node[0] not in visitedNodes:
#     visitedNodes[node[0]] = set()
#   visitedNodes[node[0]].add(node[1])
#   sameNodes = [node]
#   for nodePair in nodePairs:
#     node1 = nodePair[0]
#     node2 = nodePair[1]
#     if node == node1:
#       flag = False
#       for sameNode in sameNodes:
#         if sameNode[0] == node2[0]:
#           flag = True
#           break
#       if flag:
#         continue
#       for sameNode in findSameNodes(node2, nodePairs, visitedNodes):
#         sameNodes.append(sameNode)
#     elif node == node2:
#       flag = False
#       for sameNode in sameNodes:
#         if sameNode[0] == node1[0]:
#           flag = True
#           break
#       if flag:
#         continue
#       for sameNode in findSameNodes(node1, nodePairs, visitedNodes):
#         sameNodes.append(sameNode)
#   return sameNodes

def drawPaths(SAP, APNodes, fileName, title = None):
  g = graphviz.Digraph()
  g.attr(label = title)
  # visitedAddress = set()
  headAddresses = set()
  tailAddresses = set()
  for headAddress in SAP:
    # visitedAddress.add(headAddress)
    headAddresses.add(headAddress)
    for tailAddress in SAP[headAddress]:
      tailAddresses.add(tailAddress)
      # visitedAddress.add(tailAddress)
      g.edge(headAddress, tailAddress)
  for address in APNodes:
    # if address not in visitedAddress:
    #   continue
    node = set()
    for itemID in APNodes[address]:
      node.add(itemMapSet[itemID])
    if len(node) == 1:
      node = list(node)[0]
    g.node(address, str(node))

  g.node('RETURN')
  for tailAddress in tailAddresses:
    if tailAddress not in headAddresses or not SAP[tailAddress]:
      g.edge(tailAddress, 'RETURN')

  g.render(fileName)

def drawRules(paths, fileName, title = None):
  g = graphviz.Digraph()
  g.attr(label = title)

  nodes = set()
  for path in paths:
    head = str(path[0])
    tail = str(path[1])
    if head.isdigit():
      nodes.add(head)
    if tail.isdigit():
      nodes.add(tail)
    if path[2]:
      edge = itemMapSet[path[2]]
    else:
      edge = ''
    g.edge(head, tail, label = edge)

  for node in nodes:
    g.node(node, label = '<q<SUB>' + str(int(node) - 1) + '</SUB>>')
  g.node('F', label = '<q<SUB>F</SUB>>', shape = 'doublecircle')
  
  g.render(fileName)


def SymbolicExecutor(input, outputDir):
  cmd = ['/home/SVF-tools/SVF/SVF-example/src/svf-example', '-stat=false', '-extapi=/home/SVF-tools/SVF/node_modules/SVF/Release-build/lib/extapi.bc', input]
  # print(' '.join(cmd))
  subprocess.call(cmd)


# pragma table_info(Calls);
def IndexBuilder(outputDir, SAPDir, locationTable, itemsTable, finishedFiles):
  global locationTableID, itemsTableID
  print()
  for root, dirs, files in os.walk(outputDir):
    for file in files:
      if not file.endswith('.bc'):
        continue
      finishedFiles += 1
      print('\rIndexBuilder:', finishedFiles, end ='')
      # print(file)
      subDatabase = os.path.join(root, file)
      with open(subDatabase) as file_read:
        paths = [line.rstrip() for line in file_read]
        if paths:
          verification = paths.pop(-1)
          if verification == '-1' and paths:
            SAP = {}
            APNodes = {}
            startAPNodes = set()
            for path in paths:
              if path.startswith('FileName: '):
                fileName = path[len('FileName: '):]
                if fileName not in locationTable:
                  locationTable[fileName] = {}
              elif path.startswith('FunctionName: '):
                function = path[len('FunctionName: '):]
                # Locations
                if function not in locationTable[fileName]:
                  locationTableID += 1
                  locationTable[fileName][function] = locationTableID
                locationID = locationTable[fileName][function]
              elif path.startswith('APIName: '):
                API = path[len('APIName: '):]
                # APIs
                if API not in itemsTable:
                  itemsTableID += 1
                  itemsTable[API] = itemsTableID
                APIID = itemsTable[API]
              elif path.startswith('APIAddress: '):
                APIAddress = path[len('APIAddress: '):]
                if APIAddress not in APNodes:
                  APNodes[APIAddress] = set()
                APNodes[APIAddress].add(APIID)
                # APINode
                if APIAddress not in SAP:
                  SAP[APIAddress] = {}
                if APIID not in SAP[APIAddress]:
                  SAP[APIAddress][APIID] = {}
                if locationID not in SAP[APIAddress][APIID]:
                  SAP[APIAddress][APIID][locationID] = {}
                SAP[APIAddress][APIID][locationID][APIAddress] = set()
              elif path.startswith('APNode: '):
                APNode = path[len('APNode: '):].split('&')
                APNodeAddress = APNode[0]
                APNodeValue = APNode[1]
                if APNodeValue == 'IS_ERR(0) ICMP_EQ 0': # 将来要移到svf里面
                  APNodeValue = API + '(0) ICMP_NE 0'
                elif APNodeValue == 'IS_ERR(0) ICMP_EQ 1':
                  APNodeValue = API + '(0) ICMP_EQ 0'
                if APNodeValue not in itemsTable:
                  itemsTableID += 1
                  itemsTable[APNodeValue] = itemsTableID
                if APNodeAddress not in APNodes:
                  APNodes[APNodeAddress] = set()
                APNodes[APNodeAddress].add(itemsTable[APNodeValue])
              elif path.startswith('StartAPNode: '):
                startAPNode = path[len('StartAPNode: '):]
                startAPNodes.add(startAPNode)
              elif path.startswith('APEdge: '):
                APEdge = path[len('APEdge: '):].split('&')
                headAddress = APEdge[0]
                tailAddress = APEdge[1]

                # itemSet
                if headAddress not in SAP[APIAddress][APIID][locationID]:
                  SAP[APIAddress][APIID][locationID][headAddress] = set()
                SAP[APIAddress][APIID][locationID][headAddress].add(tailAddress)

            for APIAddress in SAP:
              for APIID in SAP[APIAddress]:
                with open(os.path.join(SAPDir, str(APIID)), 'a') as file_write:
                  for locationID in SAP[APIAddress][APIID]:
                    currentAPNodes = {}
                    currentStartAPNodes = set()
                    for headAddress in SAP[APIAddress][APIID][locationID]:
                      currentAPNodes[headAddress] = APNodes[headAddress]
                      if headAddress in startAPNodes:
                        currentStartAPNodes.add(headAddress)
                      for tailAddress in SAP[APIAddress][APIID][locationID][headAddress]:
                        currentAPNodes[tailAddress] = APNodes[tailAddress]
                        if tailAddress in startAPNodes:
                          currentStartAPNodes.add(tailAddress)
                    print(str(SAP[APIAddress][APIID][locationID]), str(currentAPNodes), locationID, currentStartAPNodes, sep = ' | ', file = file_write)
                  # cur.execute('insert into ItemSets(SAP, APNodes, API, Location) values(?, ?, ?, ?)', (str(SAP[APIAddress][APIID][locationID]), str(APNodes), APIID, locationID))
      os.remove(subDatabase)

  # conn.commit()
  print()

  # for root, dirs, files in os.walk(outputDir):
  #   for file in files:
  #     if not file.endswith('.bc'):
  #       continue
  #     os.remove(os.path.join(root, file))


def FrequentSubgraphMiner(APIID, APIName, DBDir, SFAInputFile, SFAOutputFile):
  with open(os.path.join('Rule', APIName), 'w') as file_write:
    print('start', file = file_write)
  FrequentSubgraphMinerTime = time.time()
  candidate = {}
  callerMap = {}
  with open(os.path.join(SAPDir, str(APIID)), 'r') as file_read:
    for line in file_read:
      line = line.strip()
      if line:
        itemSet = line.split(' | ')
        # itemSet = (eval(itemSet[0]), eval(itemSet[1]), int(itemSet[2]), eval(itemSet[3]))
        # itemSets.append((itemSet[0], itemSet[1], int(itemSet[2])))
        # print('itemSet: ', itemSet)
        SAP = eval(itemSet[0])
        APNodes = eval(itemSet[1])
        location = int(itemSet[2])
        # startAPNodes = eval(itemSet[3])

        # locationSetBitArray = IDSet2BitArray({location}, locationLength)
        edges = set()
        for headAddress in SAP:
          edges |= APNodes[headAddress]
          for tailAddress in SAP[headAddress]:
            edges |= APNodes[tailAddress]
        for edge in edges:
          edgeValue = itemMapSet[edge]
          if appName in debugPattern and edgeValue in debugPattern[appName]:
            continue
          edgeVars = re.match(returnPattern, edgeValue, re.M | re.I)
          if edgeVars: # 不考虑RETURN的事情，因为不知道具体的条件
            continue
          edgeVars = re.match(condPattern, edgeValue, re.M | re.I)
          if edgeVars and edgeVars.group(1) != APIName:
            continue

          if edge not in candidate:
            candidate[edge] = set()
          candidate[edge].add(location)

          callerMap[location] = set()

          # itemSubSetBitArray = IDSet2BitArray({edge}, itemLength)
          # itemSubSetBitArrayStr = itemSubSetBitArray.to01()
          # if itemSubSetBitArrayStr not in candidate:
          #   candidate[itemSubSetBitArrayStr] = IDSet2BitArray({}, locationLength)
          # candidate[itemSubSetBitArrayStr] |= locationSetBitArray
  
  if APIID not in candidate:
    print(APIID, 'not found in candidate')
    with open(os.path.join('Rule', APIName), 'w') as file_write:
      print('finish', file = file_write)
    return
  
  # print('EVP_MD_fetch:', candidate[2233])
  # print('EVP_MD_free:', candidate[2268])
  # print('EVP_MD_fetch(0) ICMP_EQ 0:', candidate[2269])
  # print('EVP_MD_fetch(0) ICMP_NE 0', candidate[2270])

  APISupport = candidate[APIID]

  frequent = {}
  for edge in candidate:
    # print('Item:', itemMapSet[edge])
    support = candidate[edge]
    # print('support:', len(support))

    if len(support) >= MIN_SUPPORT and len(support) >= MIN_CONFIDENCE * len(APISupport):
      # print('Item:', edge, itemMapSet[edge])
      frequent[edge] = candidate[edge]
      # print('support:', len(candidate[edge]))

  if len(frequent) < 2:
    # 扩充support
    for location in callerMap:
      caller = locationMapSet[location][1]
      if caller not in itemReMapSet:
        continue
      callerID = itemReMapSet[caller]
      if not os.path.exists(os.path.join(SAPDir, str(callerID))):
        continue
      with open(os.path.join(SAPDir, str(callerID)), 'r') as file_read:
        for line in file_read:
          line = line.strip()
          if line:
            itemSet = line.split(' | ')
            callerLocation = int(itemSet[2])
            if callerLocation != location:
              callerMap[location].add(callerLocation)
    APISupport = set()
    for location in candidate[APIID]:
      APISupport.add(location)
      if location in callerMap:
        APISupport |= callerMap[location]

    frequent = {}
    for edge in candidate:
      # print('Item:', itemMapSet[edge])
      support = set()
      for location in candidate[edge]:
        support.add(location)
        if location in callerMap:
          support |= callerMap[location]
      # print('support:', len(support))

      if len(support) >= MIN_SUPPORT and len(support) >= MIN_CONFIDENCE * len(APISupport):
        # print('Item:', edge, itemMapSet[edge])
        frequent[edge] = candidate[edge]
        # print('support:', len(candidate[edge]))

    if len(frequent) < 2:
      with open(os.path.join('Rule', APIName), 'w') as file_write:
        print('finish', file = file_write)
      return

  SFAItem2IDMap = {}
  SFALocation2IDMap = {}

  SFAID2ItemMap = {}
  SFAID2LocationMap = {}

  with open(SFAInputFile, 'w') as file_write:
    for edge in frequent:
      if edge not in SFAItem2IDMap:
        newID = len(SFAItem2IDMap)
        SFAItem2IDMap[edge] = newID
        SFAID2ItemMap[newID] = edge
      print(SFAItem2IDMap[edge], end = ' ', file = file_write)
      for location in frequent[edge]:
        if location not in SFALocation2IDMap:
          newID = len(SFALocation2IDMap)
          SFALocation2IDMap[location] = newID
          SFAID2LocationMap[newID] = location
        print(SFALocation2IDMap[location], end = ' ', file = file_write)
        if location in callerMap:
          for callerLocation in callerMap[location]:
            if callerLocation not in SFALocation2IDMap:
              newID = len(SFALocation2IDMap)
              SFALocation2IDMap[callerLocation] = newID
              SFAID2LocationMap[newID] = callerLocation
            print(SFALocation2IDMap[callerLocation], end = ' ', file = file_write)
        
      print(end = '\n', file = file_write)

  # print('SFAItem2IDMap:', SFAItem2IDMap)

  cmd = ['./FrequentMiner', APIName, str(SFAItem2IDMap[APIID]), SFAInputFile, SFAOutputFile, str(MIN_SUPPORT), str(MIN_CONFIDENCE), str(len(SFAItem2IDMap)), str(len(SFALocation2IDMap))]
  # print(' '.join(cmd))
  subprocess.call(cmd)
  if not os.path.exists(SFAOutputFile):
    with open(os.path.join('Rule', APIName), 'w') as file_write:
      print('finish', file = file_write)
    return

  SFADatabase = os.path.join(DBDir, APIName + '.db')
  subConn = sqlite3.connect(SFADatabase)
  subCur = subConn.cursor()
  subCur.execute('drop table if exists Rules')
  subCur.execute('create table if not exists Rules(ID integer primary key autoincrement, API integer not null, Right String not null, RightItems, Support integer not null, Locations string not null)')

  SFAPathStrs = set()
  # support = copy.deepcopy(APISupport)
  support = set()
  with open(SFAOutputFile, 'r') as file_read:
    for line in file_read:
      rightItemSubSet = set()
      sub_support = set()
      lines = line.strip().split(' | ')
      for ID in lines[0].split(' '):
        rightItemSubSet.add(SFAID2ItemMap[int(ID)])
      if len(rightItemSubSet) < 2:
        continue
      for ID in lines[1].split(' '):
        location = SFAID2LocationMap[int(ID)]
        if location in callerMap:
          sub_support.add(location)

      # if rightItemSubSet != {20354, 20516, 20517, 20518, 20395, 20500}:
      #   continue
      # print('rightItemSubSet:', rightItemSubSet)
      # print('rightItemSubSetValue:')
      # for rightItem in rightItemSubSet:
      #   print(itemMapSet[rightItem])
      # print('sub_support:', len(sub_support))

      (startSFAEdges, pattern) = SFAVote(sub_support, callerMap, APIID, rightItemSubSet, FrequentSubgraphMinerTime)
      # print('startSFAEdges:', startSFAEdges)
      # print('pattern:', pattern)

      usedTime = getUsedTime(FrequentSubgraphMinerTime)
      if usedTime > 0:
        # print('\n', APIID, APIName, 'timeout2:', usedTime)
        with open(os.path.join('Rule', APIName), 'w') as file_write:
          print('finish', file = file_write)
        return
      
      if not pattern or not startSFAEdges:
        with open(os.path.join('Rule', APIName), 'w') as file_write:
          print('finish', file = file_write)
        continue

      SFAPaths = getSFAPaths(startSFAEdges, pattern, FrequentSubgraphMinerTime)
      for SFAPath in SFAPaths:
        # newSFAPath = SFAPath
        # newSFAPath = [] # 过滤掉提前结束的路径
        # for SFAEdge in SFAPath:
        #   newSFAPath.append(SFAEdge)
        #   if SFAEdge in finalSFAEdges:
        #     break
        # print('tempnewSFAPath:', newSFAPath)
        
        if APIID in SFAPath and len(SFAPath) > 1:
          SFAPathStr = ', '.join(str(SFAEdge) for SFAEdge in SFAPath)
          SFAPathStrs.add(SFAPathStr)


      # support &= sub_support
      support |= sub_support
      # print('SFAPathStrs:', SFAPathStrs)

      usedTime = getUsedTime(FrequentSubgraphMinerTime)
      if usedTime > 0:
        # print('\n', APIID, APIName, 'timeout3:', usedTime)
        with open(os.path.join('Rule', APIName), 'w') as file_write:
          print('finish', file = file_write)
        return

  superSFAPathStrs = set()
  for i in range(len(SFAPathStrs)):
    for j in range(i + 1, len(SFAPathStrs)):
      usedTime = getUsedTime(FrequentSubgraphMinerTime)
      if usedTime > 0:
        # print('\n', APIID, APIName, 'timeout4:', usedTime)
        with open(os.path.join('Rule', APIName), 'w') as file_write:
          print('finish', file = file_write)
        return
      SFAPathStr1 = list(SFAPathStrs)[i]
      SFAPathStr2 = list(SFAPathStrs)[j]
      if SFAPathStr1 in SFAPathStr2:
        superSFAPathStrs.add(SFAPathStr2)
      elif SFAPathStr2 in SFAPathStr1:
        superSFAPathStrs.add(SFAPathStr1)
  
  # print('usedTime:', time.time() - FrequentSubgraphMinerTime)

  SFAPaths = []
  for SFAPathStr in SFAPathStrs:
    if SFAPathStr not in superSFAPathStrs:
      SFAPath = [int(SFAEdge) for SFAEdge in SFAPathStr.split(', ')]
      SFAPaths.append(SFAPath)

  # print('SFAPaths:', SFAPaths)

  SFA = SFAGenerate(SFAPaths, FrequentSubgraphMinerTime)
  # print('SFA:', SFA)

  # SFA = SFAGenerate(startSFAEdges, finalSFAEdges, pattern)

  if not SFA:
    with open(os.path.join('Rule', APIName), 'w') as file_write:
      print('finish', file = file_write)
    return
  
  rightItems = set()
  for headNode in SFA:
    for transition in SFA[headNode]:
      rightItems.add(transition)

  subCur.execute('insert into Rules(API, Right, RightItems, Support, Locations) values(?, ?, ?, ?, ?)', (APIID, str(SFA), str(rightItems), len(support), str(support)))
    
  subConn.commit()
  subCur.close()
  subConn.close()

  with open(os.path.join('Rule', APIName), 'w') as file_write:
    print('finish', file = file_write)

'''
  frequent = {}
  conditions = {}
  for itemSubSetBitArrayStr in candidate:
    # print('itemSubSetBitArrayStr')
    
    support = candidate[itemSubSetBitArrayStr].count(1)
    # debug
    # itemSubSet = bitArrayStr2IDSet(itemSubSetBitArrayStr)
    # for item in itemSubSet:
    #   if APIName in itemMapSet[item]:
    #     print('itemSubSet:', itemSubSet )
    #     print(itemMapSet[item])
    #     print('location:', bitArrayStr2IDSet(candidate[itemSubSetBitArrayStr].to01()))
    #     print('support:', support)
    #     print()
    
    if support >= MIN_SUPPORT:
      # itemSubSet = bitArrayStr2IDSet(itemSubSetBitArrayStr)
      # for item in itemSubSet:
      #   print('itemSubSet:', itemSubSet )
      #   print(itemMapSet[item])
      #   print('location:', bitArrayStr2IDSet(candidate[itemSubSetBitArrayStr].to01()))
      #   print('support:', support)
      #   print()
      frequent[itemSubSetBitArrayStr] = candidate[itemSubSetBitArrayStr]
      conditions[itemSubSetBitArrayStr] = set()

  association = {}
  subAssociation = set()
  k = 1
  while 1:
    print(k, 'edge frequent length:', len(frequent))
    if len(frequent) <= 1:
      break
    k += 1

    candidate = {}
    frequentKeys = list(frequent.keys())
    for i in range(len(frequentKeys)):
      for j in range(i + 1, len(frequentKeys)):
    # for itemSubSetBitArrayStrComb in list(itertools.combinations(frequent.keys(), 2)):
        usedTime = getUsedTime(FrequentSubgraphMinerTime)
        if usedTime > 0:
          print('\n', APIID, APIName, 'timeout1:', usedTime)
          with open(os.path.join('Rule', APIName), 'w') as file_write:
            print('finish', file = file_write)
          return
        itemSubSetBitArrayStr0 = frequentKeys[i]
        itemSubSetBitArrayStr1 = frequentKeys[j]
        itemSubSetBitArray0 = bitarray(itemSubSetBitArrayStr0)
        itemSubSetBitArray1 = bitarray(itemSubSetBitArrayStr1)
        newItemSubSetBitArray = (itemSubSetBitArray0 | itemSubSetBitArray1)
        if (newItemSubSetBitArray ^ itemSubSetBitArray0).count(1) != 1:
          continue
        # Union
        newItemSubSetBitArrayStr = newItemSubSetBitArray.to01()
        support = (frequent[itemSubSetBitArrayStr0] & frequent[itemSubSetBitArrayStr1])
        support0 = frequent[itemSubSetBitArrayStr0]
        support1 = frequent[itemSubSetBitArrayStr1]

        if support.count(1) < MIN_SUPPORT:
          continue

        isFrequent = False

        # print('item0:', bitArrayStr2IDSet(itemSubSetBitArray0.to01()), (itemSubSetBitArray0 & APIItemSubSetBitArray).count(1))
        # print('item1:', bitArrayStr2IDSet(itemSubSetBitArray1.to01()), (itemSubSetBitArray1 & APIItemSubSetBitArray).count(1))

        if (itemSubSetBitArray0 & APIItemSubSetBitArray).count(1) == 1 and support.count(1) >= support0.count(1) * MIN_CONFIDENCE: # item0包含API
          isFrequent = True
          subAssociation.add(itemSubSetBitArrayStr0)

          if newItemSubSetBitArrayStr not in association:
            association[newItemSubSetBitArrayStr] = {'support': support.to01(), 'condition': set()}
          
          if itemSubSetBitArrayStr0 in conditions:
            conditions[itemSubSetBitArrayStr0].add(newItemSubSetBitArrayStr)
            association[newItemSubSetBitArrayStr]['condition'].add(itemSubSetBitArrayStr0)
          else:
            for condition in conditions:
              if itemSubSetBitArrayStr0 in conditions[condition]:
                conditions[condition].add(newItemSubSetBitArrayStr)
                association[newItemSubSetBitArrayStr]['condition'].add(condition)

        if (itemSubSetBitArray1 & APIItemSubSetBitArray).count(1) == 1 and support.count(1) >= support1.count(1) * MIN_CONFIDENCE: # item1包含API
          isFrequent = True
          subAssociation.add(itemSubSetBitArrayStr1)

          if newItemSubSetBitArrayStr not in association:
            association[newItemSubSetBitArrayStr] = {'support': support.to01(), 'condition': set()}

          if itemSubSetBitArrayStr1 in conditions:
            conditions[itemSubSetBitArrayStr1].add(newItemSubSetBitArrayStr)
            association[newItemSubSetBitArrayStr]['condition'].add(itemSubSetBitArrayStr1)
          else:
            for condition in conditions:
              if itemSubSetBitArrayStr1 in conditions[condition]:
                conditions[condition].add(newItemSubSetBitArrayStr)
                association[newItemSubSetBitArrayStr]['condition'].add(condition)

        if isFrequent:
          candidate[newItemSubSetBitArrayStr] = (frequent[itemSubSetBitArrayStr0] & frequent[itemSubSetBitArrayStr1])
          # newItemSubSet = bitArrayStr2IDSet(newItemSubSetBitArrayStr)
          # print('newItemSubSet:', newItemSubSet)
          # for newItem in newItemSubSet:
          #   print('newItem:', itemMapSet[newItem])

        # if support >= support0 * MIN_CONFIDENCE and support >= support1 * MIN_CONFIDENCE: # 主要是将API加入到条件中
        #   candidate[newItemSubSetBitArrayStr] = (frequent[itemSubSetBitArrayStr0] & frequent[itemSubSetBitArrayStr1])
        #   # support = candidate[newItemSubSetBitArrayStr].count(1)
        #   if newItemSubSetBitArrayStr not in association:
        #     association[newItemSubSetBitArrayStr] = {'support': candidate[newItemSubSetBitArrayStr].to01(), 'condition': set()}
        #   association[newItemSubSetBitArrayStr]['condition'].add(itemSubSetBitArrayStr0)
        #   association[newItemSubSetBitArrayStr]['condition'].add(itemSubSetBitArrayStr1)

        # # Intersection 还没有完全实现
        # diffConstraints = list(item1['constraints'] ^ item2['constraints'])
        # if len(diffConstraints) == 2:
        #   cur.execute('select FunctionName, ArgumentIndex, Min, Max from Constraints where ID = ?', \
        #               (diffConstraints[0], ))
        #   constraint1 = cur.fetchone()
        #   cur.execute('select FunctionName, ArgumentIndex, Min, Max from Constraints where ID = ?', \
        #               (diffConstraints[1], ))
        #   constraint2 = cur.fetchone()
        #   if constraint1[0] == constraint2[0] and constraint1[1] == constraint2[1]: # 同一个函数同一个参数
        #     Min = max(constraint1[2], constraint2[2])
        #     Max = min(constraint1[3], constraint2[3])
        #     # print(Min, Max, Min <= Max)
        #     if Min <= Max:
        #       constraint = (constraint1[0], constraint1[1], Min, Max)
        #       cur.execute('select ID from Constraints where FunctionName = ? and ArgumentIndex = ? and Min = ? and Max = ?', constraint)
        #       ID = cur.fetchone()[0]
        #       if not ID:
        #         cur.execute('insert into Constraints(FunctionName, ArgumentIndex, Min, Max) values(?, ?, ?, ?)', constraint)
        #         cur.execute('select ID from Constraints where FunctionName = ? and ArgumentIndex = ? and Min = ? and Max = ?', constraint)
        #         ID = cur.fetchone()[0]
        #       commonConstraints = item1['constraints'] & item2['constraints']
        #       commonConstraints.add(str(ID))
        #       itemSetStr = str({'calls': unionCalls, 'constraints': commonConstraints})
        #       print('intersection CommonConstraints: ', commonConstraints)

    frequent = candidate

  # # Convert from itemSet into graph
  if not association:
    with open(os.path.join('Rule', APIName), 'w') as file_write:
      print('finish', file = file_write)
    return

  
'''


def getGraph(edges):
  graph = {}
  for edge in edges:
    head = edge['head']
    tail = edge['tail']
    value = edge['value']
    # dataRelatedAPIs = edge['dataRelatedAPIs']
    if head not in graph:
      graph[head] = {}
    # graph[head][tail] = (value, dataRelatedAPIs)
    if tail not in graph:
      graph[head][tail] = []
    graph[head][tail].append(value)
  return graph


# def getCompressedGraph(graph, rightItemSubSet, hasReturn = False): # 有重大问题，特别是visited，弃用，全部统一在DFS
#   visitedNodes = set()
#   queueNode = [('1', '1')]
#   compressedGraph = {}
#   while queueNode:
#     node = queueNode.pop(0)
#     lastNode = node[0]
#     currentNode = node[1]
#     if currentNode in visitedNodes:
#       continue
#     visitedNodes.add(currentNode)
#     if currentNode not in graph:
#       continue
#     for nextNode in graph[currentNode]:
#       # value = graph[currentNode][nextNode][0]
#       # dataRelatedAPIs = graph[currentNode][nextNode][1]
#       # if left not in dataRelatedAPIs or value not in rightItemSubSet:
#       values = graph[currentNode][nextNode]
#       frequentValues = set()
#       for value in values:
#         if value in rightItemSubSet:
#           frequentValues.add(value)
#         elif hasReturn: # RETURN也得加上
#           valueValue = itemMapSet[value]
#           if valueValue.startswith('RETURN '):
#             frequentValues.add(value)
#       if not frequentValues:
#         queueNode.append((lastNode, nextNode))
#       else:
#         if lastNode not in compressedGraph:
#           compressedGraph[lastNode] = {}
#         compressedGraph[lastNode][nextNode] = frequentValues
#         queueNode.append((nextNode, nextNode))
#   return compressedGraph


# def getStartSFAEdgeAddresses(SAP, APNodes, startAPNodes, rightItems, startSFAEdgeAddresses):
def getStartSFAEdges(SAP, APNodes, startAPNodes, rightItems, startSFAEdges):
  prevNodeAddresses = copy.deepcopy(startAPNodes)
  visitedNodeAddresses = set()

  while prevNodeAddresses:
    prevNodeAddress = prevNodeAddresses.pop()

    if prevNodeAddress in visitedNodeAddresses:
      continue
    visitedNodeAddresses.add(prevNodeAddress)

    hasSFAEdges = False
    for prevSAPEdge in APNodes[prevNodeAddress]:
      # print('prevSAPEdge:', prevSAPEdge, itemMapSet[prevSAPEdge])
      if prevSAPEdge in rightItems:
        # if prevSAPEdge not in startSFAEdgeAddresses:
        #   startSFAEdgeAddresses[prevSAPEdge] = set()
        # startSFAEdgeAddresses[prevSAPEdge].add(prevNodeAddress)
        startSFAEdges.add(prevSAPEdge)
        hasSFAEdges = True
    if not hasSFAEdges and prevNodeAddress in SAP:
      for nextNodeAddress in SAP[prevNodeAddress]:
        prevNodeAddresses.add(nextNodeAddress)
        
  # return startSFAEdgeAddresses
  return startSFAEdges


def getNextSFAEdges(SAP, APNodes, SFAEdge, rightItems, APIID = None, translatorFlag = False):
  nextSFAEdges = set()
  prevNodeAddresses = set()
  
  for nodeAddress in APNodes:
    if SFAEdge in APNodes[nodeAddress]:
      prevNodeAddresses.add(nodeAddress)

  visitedNodeAddresses = set()
  while prevNodeAddresses:
    prevNodeAddress = prevNodeAddresses.pop()
    # print('prevNodeAddress:', prevNodeAddress, APNodes[prevNodeAddress])
    if prevNodeAddress not in SAP:
      if not translatorFlag:
        return set() # 避免SFA太精确导致跨文件误报
      continue
    if prevNodeAddress in visitedNodeAddresses:
      continue
    visitedNodeAddresses.add(prevNodeAddress)

    for nextNodeAddress in SAP[prevNodeAddress]:
      hasSFAEdges = False
      for nextSAPEdge in APNodes[nextNodeAddress]:
        # print('nextSAPEdge:', nextSAPEdge)
        nextSAPEdgeValue = itemMapSet[nextSAPEdge]
        nextSAPEdgeVars = re.match(returnPattern, nextSAPEdgeValue, re.M | re.I)
        if nextSAPEdge == SFAEdge:
          continue
        elif isOppositeCondition(SFAEdge, nextSAPEdge):
          continue
        elif translatorFlag and nextSAPEdgeVars and nextSAPEdgeVars.group(1) == itemMapSet[APIID]:
          nextSFAEdges.add(nextSAPEdge)
          hasSFAEdges = True
        elif nextSAPEdge in rightItems:
          nextSFAEdges.add(nextSAPEdge)
          hasSFAEdges = True
      if not hasSFAEdges:
        prevNodeAddresses.add(nextNodeAddress)
  return nextSFAEdges


# def DFS(graph, startNode, APIID, rightItems, hasReturn = False):
#   stack = [(startNode, {' '})]
#   pathStrList = []
#   memo = {}
#   startTime = time.time()
#   while stack:

#     usedTime = time.time() - startTime
#     if usedTime > 60:
#       return pathStrList

#     item = stack.pop()
#     currentNode = item[0]
#     currentPaths = item[1]

#     # print('currentNode:', currentNode)
#     # print('currentPaths:', currentPaths)
#     # print('memo:', memo)

#     # 是否为终点
#     if currentNode not in graph:
#       # 去除不包含API的路径
#       pathStrs = set()
#       for currentPath in currentPaths:
#         if ' ' + str(APIID) + ' ' in currentPath:
#           # print('currentPathValues:', currentPath)
#           pathStrs.add(currentPath)
#       if pathStrs:
#         pathStrList.append(pathStrs)
#       continue

#     # 是否在同一个上下文下访问过同一个节点
#     newCurrentPaths = copy.deepcopy(currentPaths)

#     if currentNode in memo:
#       for currentPath in currentPaths:
#         if currentPath in memo[currentNode]:
#           newCurrentPaths.remove(currentPath)

#     if not newCurrentPaths: # 不能加进去，不然会导致路径碎片，而且完整的路径已经加进去了
#       continue

#     if currentNode not in memo:
#       memo[currentNode] = set()
#     for currentPath in currentPaths:
#       memo[currentNode].add(currentPath)

#     for nextNode in graph[currentNode]:
#       nextPaths = set()
#       relatedEdgeValues = set()

#       edgeValues = graph[currentNode][nextNode]
#       for edgeValue in edgeValues:
#         if edgeValue in rightItems:
#           relatedEdgeValues.add(edgeValue)
#         elif hasReturn:
#           edgeValueValue = itemMapSet[edgeValue]
#           if edgeValueValue.startswith('RETURN '):
#             relatedEdgeValues.add(edgeValue)

#       if relatedEdgeValues:
#         for relatedEdgeValue in relatedEdgeValues:
#           for newCurrentPath in newCurrentPaths:
#             usedTime = time.time() - startTime
#             if usedTime > 60:
#               return pathStrList
            
#             nextPath = newCurrentPath + str(relatedEdgeValue) + ' '
#             nextPaths.add(nextPath)
#       else:
#         for newCurrentPath in newCurrentPaths:
#           nextPaths.add(newCurrentPath)

#       stack.append((nextNode, nextPaths))

#   return pathStrList


# def pathSplit(path):
#   startTime = time.time()
#   splitPaths = []
#   for edges in path:
#     if not splitPaths:
#       for edge in edges:
#         splitPaths.append([edge])
#     else:
#       newSplitPaths = []
#       for splitPath in splitPaths:
#         for edge in edges:
#           usedTime = time.time() - startTime
#           if usedTime > 60:
#             return []
          
#           newSplitPath = copy.deepcopy(splitPath)
#           if splitPath[-1] != edge and not isSameCondition(splitPath[-1], edge): # 禁止连续相同的操作 
#             newSplitPath.append(edge)
#           newSplitPaths.append(newSplitPath)
#       splitPaths = newSplitPaths
#   return splitPaths

  # splitPaths = []
  # startTime = time.time()
  # for edges in path:
  #   oldSplitPaths = copy.deepcopy(splitPaths)
  #   splitPaths = []
  #   if not oldSplitPaths:
  #     for edge in edges:
  #       splitPaths.append([edge])
  #   else:
  #     for oldSplitPath in oldSplitPaths:
  #       for edge in edges:

  #         usedTime = time.time() - startTime
  #         if usedTime > 60:
  #           return [] # 超时的路径必须舍去
          
  #         splitPath = copy.deepcopy(oldSplitPath)
  #         if splitPath[-1] != edge:
  #           splitPath.append(edge)
  #         splitPaths.append(splitPath)
  # return splitPaths


def SFAVote(support, callerMap, APIID, rightItemSubSet, FrequentSubgraphMinerTime):
  totalSupport = set()
  for location in support:
    totalSupport.add(location)
    if location in callerMap:
      totalSupport |= callerMap[location]
  # countStartEdges = {}
  # startSFAEdgeAddresses = {}
  countPaths = {}
  startSFAEdges = set()
  # with open(os.path.join(SAPDir, str(APIID)), 'r') as file_read:
  #   line_sum = sum(1 for line in file_read)
  with open(os.path.join(SAPDir, str(APIID)), 'r') as file_read:
    # line_count = 0
    # print()
    for line in file_read:
      # line_count += 1
      # print('\rline_count:', line_count, '/', line_sum, end = '')
      usedTime = getUsedTime(FrequentSubgraphMinerTime)
      if usedTime > 0:
        # print('\n', APIID, APIName, 'timeout3:', usedTime)
        return (set(), {})
      line = line.strip()
      if line:
        itemSet = line.split(' | ')
        SAP = eval(itemSet[0])
        APNodes = eval(itemSet[1])
        location = int(itemSet[2])
        startAPNodes = eval(itemSet[3])
        # itemSet = (itemSet[0], itemSet[1], int(itemSet[2]))
        if location in support:
          # print('location:', location)
          # if location != 17701:
          #   continue
          # SFAEdgeOrder = {}
          # getStartSFAEdgeAddresses(SAP, APNodes, startAPNodes, rightItemSubSet, startSFAEdgeAddresses)
          getStartSFAEdges(SAP, APNodes, startAPNodes, rightItemSubSet, startSFAEdges)
          # print('startSFAEdges:', startSFAEdges)
          # startSFAEdges |= set(startSFAEdgeAddresses.keys())

          # for startSFAEdge in startSFAEdges:
          #   if startSFAEdge not in countStartEdges:
          #     countStartEdges[startSFAEdge] = set()
          #   countStartEdges[startSFAEdge].add(location)
          for rightItem in rightItemSubSet:
            if rightItem not in countPaths:
              countPaths[rightItem] = {}
            # print('rightItem:', rightItem, itemMapSet[rightItem])
            nextSFAEdges = getNextSFAEdges(SAP, APNodes, rightItem, rightItemSubSet)
            # print('nextSFAEdges:', nextSFAEdges)
            for nextSFAEdge in nextSFAEdges:
              if nextSFAEdge not in countPaths[rightItem]:
                countPaths[rightItem][nextSFAEdge] = set()
              countPaths[rightItem][nextSFAEdge].add(location)
  # print('countPaths')
  # print(countPaths)
  
  pattern = {}
  for headSFAEdge in countPaths:
    for tailSFAEdge in countPaths[headSFAEdge]:
      pathSupport = set()
      for location in countPaths[headSFAEdge][tailSFAEdge]:
        pathSupport.add(location)
        if location in callerMap:
          pathSupport |= callerMap[location]
      if len(pathSupport) >= len(totalSupport) * SFA_VOTE:

        # if headSFAEdge in countStartEdges and len(countStartEdges[headSFAEdge]) >= len(support) * SFA_VOTE:
        #   startSFAEdges.add(headSFAEdge)
        # if tailSFAEdge in countStartEdges and len(countStartEdges[tailSFAEdge]) >= len(support) * SFA_VOTE:
        #   startSFAEdges.add(tailSFAEdge)

        if headSFAEdge not in pattern:
          pattern[headSFAEdge] = set()
        pattern[headSFAEdge].add(tailSFAEdge)
    

    # totalLocations = set()
    # for pathStr2 in countPaths:
    #   usedTime = getUsedTime(FrequentSubgraphMinerTime)
    #   if usedTime > 0:
    #     return set()
      
    #   if pathStr1 in pathStr2:
    #     totalLocations |= countPaths[pathStr2]
    # if len(totalLocations) >= len(graphList) * SFA_VOTE:
    #   pattern.add(pathStr1)
  return (startSFAEdges, pattern)

  # visitedNodes = {}
  # visitedEdges = {}
  # queueNode = [(list(rightItemSubSet)[0], 0), (list(rightItemSubSet)[0], 1)]
  # nodePairs = []
  # paths = []
  # while queueNode:
  #   node = queueNode.pop(0)
  #   print('node:', queryIDSet({node[0]}, 'Items')[0], node[1])
  #   if node[0] in visitedNodes and node[1] in visitedNodes[node[0]]:
  #     continue
  #   if node[0] not in visitedNodes:
  #     visitedNodes[node[0]] = set()
  #   visitedNodes[node[0]].add(node[1])
  #   countEdges = {}
  #   for location in compressedGraphs:
  #     compressedGraph = compressedGraphs[location]
  #     newEdges = set()
  #     for head1 in compressedGraph:
  #       for tail1 in compressedGraph[head1]:
  #         if compressedGraph[head1][tail1] == node[0]:
  #           if node[1] == 0: # head of edge
  #             for head2 in compressedGraph:
  #               if head1 in compressedGraph[head2]: # find the previous edge
  #                 newEdge = compressedGraph[head2][head1]
  #                 newEdges.add(newEdge)
  #           else: # tail of edge
  #             if tail1 in compressedGraph: # find the next edge
  #               for tail2 in compressedGraph[tail1]:
  #                 newEdge = compressedGraph[tail1][tail2]
  #                 newEdges.add(newEdge)
  #     for newEdge in newEdges:
  #       print('newEdge:', queryIDSet({newEdge}, 'Items')[0])
  #       if newEdge not in countEdges:
  #         countEdges[newEdge] = 0
  #       countEdges[newEdge] += 1
  #   commonEdges = set()
  #   for newEdge in countEdges:
  #     if countEdges[newEdge] >= len(compressedGraphs) * SFA_VOTE:
  #       commonEdges.add(newEdge)
  #   # normalize node number
  #   for newEdge in commonEdges:
  #     if node[1] == 0:
  #       # avoid duplicate edges
  #       if newEdge in visitedEdges and node[0] in visitedEdges[newEdge]:
  #         continue
  #       if newEdge not in visitedEdges:
  #         visitedEdges[newEdge] = set()
  #       visitedEdges[newEdge].add(node[0])
  #       nodePairs.append(((newEdge, 1), node))
  #     else:
  #       # avoid duplicate edges
  #       if node[0] in visitedEdges and newEdge in visitedEdges[node[0]]:
  #         continue
  #       if node[0] not in visitedEdges:
  #         visitedEdges[node[0]] = set()
  #       visitedEdges[node[0]].add(newEdge)
  #       nodePairs.append(((newEdge, 0), node))
  #     queueNode.append((newEdge, 0))
  #     queueNode.append((newEdge, 1))
  # print('visitedEdges:', visitedEdges)
  # print('nodePairs:', nodePairs)
  # nodeNumber = {}
  # nodeCount = 0
  # visitedNodes = {}
  # for edge in rightItemSubSet:
  #   if edge not in nodeNumber or 0 not in nodeNumber[edge]:
  #     node = (edge, 0)
  #     sameNodes = findSameNodes(node, nodePairs, visitedNodes)
  #     print('sameNodes:', sameNodes)
  #     nodeCount += 1
  #     for sameNode in sameNodes:
  #       if sameNode[0] not in nodeNumber:
  #         nodeNumber[sameNode[0]] = {}
  #       nodeNumber[sameNode[0]][sameNode[1]] = nodeCount
  #   if edge not in nodeNumber or 1 not in nodeNumber[edge]:
  #     node = (edge, 1)
  #     sameNodes = findSameNodes(node, nodePairs, visitedNodes)
  #     print('sameNodes:', sameNodes)
  #     nodeCount += 1
  #     for sameNode in sameNodes:
  #       if sameNode[0] not in nodeNumber:
  #         nodeNumber[sameNode[0]] = {}
  #       nodeNumber[sameNode[0]][sameNode[1]] = nodeCount
  # for edge in rightItemSubSet:
  #   paths.append((nodeNumber[edge][0], nodeNumber[edge][1], edge))
  # return paths


def getStarts(SAP, right, nodes):
  unstarts = set()
  for head in SAP:
    for tail in SAP[head]:
      unstarts.add(tail)

  starts = set()
  for head in SAP:
    if head not in unstarts:
      starts.add(head)
  
  if not starts:
    for head in SAP:
      starts.add(head)

  return starts


def getFinalSFAEdges(patterns):
  infinalSFAEdges = set()
  for headSFAEdge in patterns:
    infinalSFAEdges.add(headSFAEdge)

  finalSFAEdges = set()
  for headSFAEdge in patterns:
    for tailSFAEdge in patterns[headSFAEdge]:
      if tailSFAEdge not in infinalSFAEdges:
        finalSFAEdges.add(tailSFAEdge)
  
  return finalSFAEdges


def getSAPPaths(startSAPNodes, SAP):
  workList = []
  visited = {}
  SAPPaths = []
  SAPNodes = set()
  startTime = time.time()
  for startSAPNode in startSAPNodes:
    workList.append((startSAPNode, []))
  while workList:
    usedTime = time.time() - startTime
    if usedTime > 60:
      return (set(), [])
    work = workList.pop()
    currSAPNode = work[0]
    currSAPPath = work[1]
    
    SAPNodes.add(currSAPNode)

    if currSAPPath:
      prevSAPNode = currSAPPath[-1]
      if prevSAPNode == currSAPNode: # 消除自环
        continue
    
    hasVisited = False
    if currSAPNode in visited:
      for visitedPath in visited[currSAPNode]:
        usedTime = time.time() - startTime
        if usedTime > 60:
          return (set(), [])
        if set(currSAPPath) == visitedPath:
          hasVisited = True
    if hasVisited:
      SAPPaths.append(copy.deepcopy(currSAPPath))
      continue

    if currSAPNode not in visited:
      visited[currSAPNode] = []
    visited[currSAPNode].append(set(currSAPPath))
    
    currSAPPath.append(currSAPNode)

    if currSAPNode in SAP:
      for nextSAPNode in SAP[currSAPNode]:
        workList.append((nextSAPNode, copy.deepcopy(currSAPPath)))
    else:
      SAPPaths.append(copy.deepcopy(currSAPPath))
  
  return (SAPNodes,SAPPaths)


def getSFAPaths(startSFAEdges, patterns, FrequentSubgraphMinerTime):
  # finalSFAEdges = getFinalSFAEdges(patterns)
  # if not finalSFAEdges:
  #   return {}
  # print('finalEdges:', finalSFAEdges)

  # startSFAEdges = getStarts(patterns)
  # if not startSFAEdges:
  #   for headSFAEdge in patterns:
  #     if headSFAEdge not in finalSFAEdges:
  #       startSFAEdges.add(headSFAEdge)
  #       break
  # print('startEdges:', startSFAEdges)

  workList = []
  # visited = {}
  SFAPaths = []
  # finalSFAEdges = set()
  for startSFAEdge in startSFAEdges:
    workList.append((startSFAEdge, []))
  while workList:
    usedTime = getUsedTime(FrequentSubgraphMinerTime)
    if usedTime > 0:
      # print('\n', APIID, APIName, 'timeout3:', usedTime)
      return
    work = workList.pop()
    currSFAEdge = work[0]
    currSFAPath = work[1]

    if currSFAPath:
      prevSFAEdge = currSFAPath[-1]
      if prevSFAEdge == currSFAEdge: # 消除自环
        continue
      # 去掉先检查返回值再调用的路径
      currSFAEdgeValue = itemMapSet[currSFAEdge]
      currSFAEdgeVars = re.match(condPattern, currSFAEdgeValue, re.M | re.I)
      if currSFAEdgeVars:
        # print('currSFAEdgeValue:', currSFAEdgeVars)
        callee = currSFAEdgeVars.group(1)
        calleePos = currSFAEdgeVars.group(2)
        if calleePos == '0':
          hasCallee = False
          for prevSFAEdge in currSFAPath:
            prevSFAEdgeValue = itemMapSet[prevSFAEdge]
            if prevSFAEdgeValue == callee:
              hasCallee = True
              break
          if not hasCallee:
            # print('No Callee:', currSFAPath, currSFAEdge)
            continue
      # 去掉互斥的条件
      hasOpposite = False
      for prevSFAEdge in currSFAPath:
        if isOppositeCondition(prevSFAEdge, currSFAEdge):
          hasOpposite = True
          break
      if hasOpposite:
        # print('Opposite:', currSFAPath, currSFAEdge)
        continue
    
    # hasVisited = False
    # if currSFAEdge in visited:
    #   for visitedPath in visited[currSFAEdge]:
    #     if set(currSFAPath) == visitedPath:
    #       hasVisited = True
    # if hasVisited:
    #   # if currSFAPath[-1] == 192489:
    #   #   print('currSFAPath:', end = ' ')
    #   #   for SFAEdge in currSFAPath:
    #   #     print(itemMapSet[SFAEdge], end = ' ')
    #   #   print()
    #   finalSFAEdges.add(currSFAPath[-1])
    #   SFAPaths.append(copy.deepcopy(currSFAPath))
    #   continue
    if currSFAEdge in currSFAPath:
      SFAPaths.append(copy.deepcopy(currSFAPath))
      continue

    # if currSFAEdge not in visited:
    #   visited[currSFAEdge] = []
    # visited[currSFAEdge].append(set(currSFAPath))
    
    currSFAPath.append(currSFAEdge)

    if currSFAEdge in patterns:
      for nextSFAEdge in patterns[currSFAEdge]:
        workList.append((nextSFAEdge, copy.deepcopy(currSFAPath)))
    else:
      # finalSFAEdges.add(currSFAPath[-1])
      SFAPaths.append(copy.deepcopy(currSFAPath))
  
  return SFAPaths
  
  # print('finalSFAEdges:', finalSFAEdges)
  # for SFAPath in SFAPaths:
  #   print('SFAPath:', end = ' ')
  #   for SFAEdge in SFAPath:
  #     print(itemMapSet[SFAEdge], end = ' ')
  #   print()

  # 去掉超集
  # newStartSFAEdges = set()
  # newFinalSFAEdges = set()
  # newPattterns = {}

  # for newSFAPathStr in newSFAPathStrs:
  #   if newSFAPathStr not in superSFAPathStrs:
  #     newSFAPath = [int(SFAEdge) for SFAEdge in newSFAPathStr.split(', ')]
  #     newSFAPaths.append(newSFAPath)
  #     # print('newSFAPath:', newSFAPath)
  #     # newStartSFAEdges.add(newSFAPath[0])
  #     # newFinalSFAEdges.add(newSFAPath[-1])
  #     # for i in range(0, len(newSFAPath) - 1):
  #     #   prevSFAEdge = newSFAPath[i]
  #     #   nextSFAEdge = newSFAPath[i + 1]
  #     #   if prevSFAEdge not in newPattterns:
  #     #     newPattterns[prevSFAEdge] = set()
  #     #   newPattterns[prevSFAEdge].add(nextSFAEdge)
  
  # # return (newStartSFAEdges, newFinalSFAEdges, newPattterns)


# def SFAGenerate(startSFAEdges, finalSFAEdges, pattern):
#   nodeTotal = 1
#   prevNodeNum = nodeTotal

#   nodeNum = {}
#   for finalSFAEdge in finalSFAEdges:
#     nodeNum[finalSFAEdge] = 'F'

#   workList = []
#   visited = {}
#   SFA = {}

#   for startSFAEdge in startSFAEdges:
#     workList.append((prevNodeNum, -1, startSFAEdge))

#   while workList:
#     work = workList.pop()
#     prevNodeNum = work[0]
#     prevSFAEdge = work[1]
#     currSFAEdge = work[2]

#     if prevSFAEdge == currSFAEdge: # 消除自环
#       continue
#     if prevSFAEdge in visited and currSFAEdge in visited[prevSFAEdge]:
#       continue
    
#     if prevSFAEdge not in visited:
#       visited[prevSFAEdge] = set()
#     visited[prevSFAEdge].add(currSFAEdge)

#     if currSFAEdge in nodeNum:
#       currNodeNum = nodeNum[currSFAEdge]
#     else:
#       nodeTotal += 1
#       currNodeNum = nodeTotal
#       nodeNum[currSFAEdge] = currNodeNum

#     if str(prevNodeNum) not in SFA:
#       SFA[str(prevNodeNum)] = {}
#     SFA[str(prevNodeNum)][currSFAEdge] = str(currNodeNum)

#     if currSFAEdge in pattern:
#       for nextSFAEdge in pattern[currSFAEdge]:
#         workList.append((currNodeNum, currSFAEdge, nextSFAEdge))

def SFAGenerate(SFAPaths, FrequentSubgraphMinerTime):
  SFA = {}
  nodeNumber = 1
  SFAWorklist = []
  for SFAPath in SFAPaths:
    SFAPathCur = 0
    SFANode = '1'
    SFAWorklist.append((SFAPath, SFAPathCur, SFANode))
  
  while SFAWorklist:
    usedTime = getUsedTime(FrequentSubgraphMinerTime)
    if usedTime > 0:
      return {}
    
    SFAWork = SFAWorklist.pop()
    SFAPath = SFAWork[0]
    SFAPathCur = SFAWork[1]
    SFANode = SFAWork[2]
    if SFAPathCur >= len(SFAPath):
      continue
    if SFAPathCur == len(SFAPath) - 1:
      if SFANode not in SFA:
        SFA[SFANode] = {}
      SFA[SFANode][SFAPath[SFAPathCur]] = 'F'
      continue
    if SFANode not in SFA or SFAPath[SFAPathCur] not in SFA[SFANode]: # 判断是否已经有这条转移规则
      # 增加一条转移规则
      nodeNumber += 1
      if SFANode not in SFA:
        SFA[SFANode] = {}
      SFA[SFANode][SFAPath[SFAPathCur]] = str(nodeNumber)
    # 更新pattern信息
    SFAWorklist.append((SFAPath, SFAPathCur + 1, SFA[SFANode][SFAPath[SFAPathCur]]))
  return SFA

  

  # patternProgress = []
  # for pattern in patterns:
  #   patternCur = 0
  #   SFANode = '1'
  #   patternProgress.append((pattern, patternCur, SFANode))
  # SFA = {}
  # inFinalNodes = set()
  # nodeNumber = 1
  # # 目前只合并开头
  # while patternProgress:
  #   newPatternProgress = []
  #   for item in patternProgress:
  #     pattern = item[0]
  #     patternCur = item[1]
  #     SFANode = item[2]
  #     if patternCur >= len(pattern):
  #       continue
  #     if SFANode not in SFA or pattern[patternCur] not in SFA[SFANode]: # 判断是否已经有这条转移规则
  #       # 增加一条转移规则
  #       nodeNumber += 1
  #       if SFANode not in SFA:
  #         SFA[SFANode] = {}
  #       SFA[SFANode][pattern[patternCur]] = str(nodeNumber)
  #       # 新增非终点节点
  #       inFinalNodes.add(SFANode)
  #     # 更新pattern信息
  #     newPatternProgress.append((pattern, patternCur + 1, SFA[SFANode][pattern[patternCur]]))
  #   patternProgress = newPatternProgress
  # # 将终点节点改为“F”
  # for num in range(1, nodeNumber + 1):
  #   if str(num) not in inFinalNodes:
  #     for node1 in SFA:
  #       for edge in SFA[node1]:
  #         node2 = SFA[node1][edge]
  #         if node2 not in inFinalNodes:
  #           SFA[node1][edge] = 'F'
  # return SFA
          

def SFACombine():
  cur.execute('drop table if exists Rules')
  cur.execute('create table if not exists Rules(ID integer primary key autoincrement, API integer not null, Right string not null, RightItems string not null, Support integer not null, Locations string not null)')
  SFADir = os.path.join(outputDir, 'SFA', 'DB')
  for root, dirs, files in os.walk(SFADir):
    for file in files:
      if file.endswith('.db'):
        SFADatabase = os.path.join(root, file)
        subConn = sqlite3.connect(SFADatabase)
        subCur = subConn.cursor()
        subCur.execute('select API, Right, RightItems, Support, Locations from Rules')
        rules = subCur.fetchall()
        for rule in rules:
          cur.execute('insert into Rules(API, Right, RightItems, Support, Locations) values(?, ?, ?, ?, ?)', (rule[0], rule[1], rule[2], rule[3], rule[4]))
        subCur.close()
        subConn.close()
  conn.commit()

  shutil.rmtree(os.path.join(outputDir, 'SFA'))


# def Translator(rule, violationDir):
#   ruleID = rule[0]
#   # print('ruleID:', ruleID)
#   APIID = rule[1]
#   right = eval(rule[2])
#   APIName = itemMapSet[APIID]
#   violationDatabase = os.path.join(violationDir, APIName + '.db')
#   subConn = sqlite3.connect(violationDatabase)
#   subCur = subConn.cursor()
#   subCur.execute('drop table if exists Violations')
#   subCur.execute('create table if not exists Violations(ID integer primary key autoincrement, Locations string not null, Rule integer not null)')
#   violatedLocations = {}
#   # validLocations = set()
#   with open(os.path.join(SAPDir, str(APIID)), 'r') as file_read:
#     lineNo = 0
#     for line in file_read:
#       lineNo += 1
#       line = line.strip()
#       if line:
#         itemSet = line.split(' | ')
#         itemSet = (lineNo, itemSet[0], itemSet[1], int(itemSet[2]))
#         # if itemSet[0] != 90482:
#         #   continue
#         # itemSetID = itemSet[0]
#         # print('itemSetID:', itemSet[0])
#         SAP = eval(itemSet[1])
#         APNodes = eval(itemSet[2])
#         location = itemSet[3]
#         if location != 776916:
#           continue
#         print('location:', location)
        
#         result = translate(SAP, APNodes, APIID, right)
#         if not result[0]:
#           # print('itemSet:', itemSet)
#           if location not in violatedLocations:
#             violatedLocations[location] = set()
#           violatedLocations[location].add(str(result[1]))
#   subCur.execute('insert into Violations(Locations, Rule) values(?, ?)', (str(violatedLocations), ruleID))
#   subConn.commit()


def Translator(APIID, right, rightItems, ruleID, SAPDir, violatedAPIDir):
  callerLocation = set()
  # rightTemp = copy.deepcopy(right)
  # for startNode in rightTemp:
  #   for transition in rightTemp[startNode]:
  #     endNode = rightTemp[startNode][transition]
  #     transitionValueVars = re.match(condPattern, itemMapSet[transition], re.M | re.I)
  #     if transitionValueVars:
  #       newTransitionValue = 'RETURN ' + transitionValueVars.group(1) + '(' + transitionValueVars.group(2) + ')'
  #       if newTransitionValue in itemReMapSet: # 说明存在SAP有RETURN API(X)
  #         newTransition = itemReMapSet[newTransitionValue]
  #         rightItems.add(newTransition)
  #         right[startNode][newTransition] = endNode

  transitionChild = {}
  for rightItem in rightItems:
    transitionChild[rightItem] = set()
    works = [('1', False)]
    while works:
      work = works.pop(0)
      currNode = work[0]
      flag = work[1]
      if currNode not in right:
        continue
      for transition in right[currNode]:
        if flag:
          transitionChild[rightItem].add(transition)
        if transition == rightItem:
          works.append((right[currNode][transition], True))
        else:
          works.append((right[currNode][transition], flag))
  # print(transitionChild)

  with open(os.path.join(SAPDir, str(APIID)), 'r') as file_read:
    lineNo = 0
    for line in file_read:
      lineNo += 1
      line = line.strip()
      if line:
        itemSet = line.split(' | ')
        SAP = eval(itemSet[0])
        
        # Large paths are often false positives caused by errors in static analysis.
        # SAPNodes = set()
        # SFAEdgesNum = 0
        # for headNode in SAP:
        #   SAPNodes.add(headNode)
        #   SFAEdgesNum += len(SAP[headNode])
        #   for tailNode in SAP[headNode]:
        #     SAPNodes.add(tailNode)
        # if len(SAPNodes) > 30:
        #   continue
        # if SFAEdgesNum > 100:
        #   continue

        APNodes = eval(itemSet[1])
        location = int(itemSet[2])
        startSAPNodeAddresses = eval(itemSet[3])
        
        # if itemSet[0] != 90482:
        #   continue
        # itemSetID = itemSet[0]
        # print('itemSetID:', itemSet[0])

        # if lineNo != 140:
        #   continue
        # fileFunction = locationMapSet[location]
        # if fileFunction[0] != 'ssl/statem/statem_srvr.c': #or fileFunction[1] != 'allocate_flows':
        #   continue
        # print('location:', lineNo, location, fileFunction)

        violatedFile = os.path.join(violatedAPIDir, str(lineNo))

        startRightItems = set(right['1'].keys())
        # newStartSAPNodeAddresses = set()
        # print('startRightItems:', startRightItems)
        
        # startSFAEdgeAddresses = {}
        # getStartSFAEdgeAddresses(SAP, APNodes, startSAPNodeAddresses, rightItems, startSFAEdgeAddresses)
        startSAPNodes = set()
        newAPNodes = copy.deepcopy(APNodes)
        for nodeAddress in APNodes:
          for SAPEdge in APNodes[nodeAddress]:
            SAPEdgeValue = itemMapSet[SAPEdge]
            if SAPEdgeValue in clusterAPI:
              newAPNodes[nodeAddress].add(itemReMapSet[clusterAPI[SAPEdgeValue]])
            SAPEdgeValueVars = re.match(condPattern, SAPEdgeValue, re.M | re.I)
            if SAPEdgeValueVars and SAPEdgeValueVars.group(3) == 'ICMP_NE' and SAPEdgeValueVars.group(4) == '0':
              newSAPEdgeValue = SAPEdgeValueVars.group(1) + '(' + SAPEdgeValueVars.group(2) + ')' + 'ICMP_EQ 1'
              if newSAPEdgeValue in itemReMapSet:
                newAPNodes[nodeAddress].add(itemReMapSet[newSAPEdgeValue])

        getStartSFAEdges(SAP, newAPNodes, startSAPNodeAddresses, startRightItems, startSAPNodes)
        if not startSAPNodes:
          for prevNodeAddress in SAP:
            for prevSAPEdge in APNodes[prevNodeAddress]:
              if prevSAPEdge in rightItems:
                startSAPNodes.add(prevSAPEdge)

            for nextNodeAddress in SAP[prevNodeAddress]:
              for nextSAPEdge in APNodes[nextNodeAddress]:
                if nextSAPEdge in rightItems:
                  startSAPNodes.add(nextSAPEdge)

        if not startSAPNodes:
          with open(violatedFile, 'w') as file_write:
            print((ruleID, location), file = file_write)
            # print('no startSAPNodes')
          continue

        # print('APNodes:', APNodes)
        # print('startSFAEdgeAddresses:', startSFAEdgeAddresses)
        # for startRightItem in startRightItems:
        #   if startRightItem not in startSFAEdgeAddresses:
        #     continue
        #   newStartSAPNodeAddresses |= startSFAEdgeAddresses[startRightItem]
        # startSAPNodes = startSFAEdges & startRightItems
        # print('startSAPNodes', startSAPNodes)
        
        compressedSAP = {} # 以后得把Return加进来
        # if appName == 'httpd':
        #   for prevNodeAddress in SAP:
        #     flag = False
        #     for prevSAPEdge in APNodes[prevNodeAddress]:
        #       if prevSAPEdge in rightItems:
        #         flag = True
        #         break
        #     if not flag:
        #       prevSAPEdge = prevNodeAddress
        #     if prevSAPEdge not in compressedSAP:
        #       compressedSAP[prevSAPEdge] = set()

        #     for nextNodeAddress in SAP[prevNodeAddress]:
        #       flag = False
        #       for nextSAPEdge in APNodes[nextNodeAddress]:
        #         if nextSAPEdge in rightItems:
        #           flag = True
        #           break
        #       if not flag:
        #         nextSAPEdge = nextNodeAddress
        #         compressedSAP[prevSAPEdge].add(nextSAPEdge)
        # else:
        for rightItem in rightItems:
          # if rightItem != 1909:
          #   continue
          # print('rightItem:', rightItem, itemMapSet[rightItem])
          nextSFAEdges = getNextSFAEdges(SAP, newAPNodes, rightItem, rightItems, APIID, True)
          newNextSFAEdges = set()
          for nextSFAEdge in nextSFAEdges:
            # print('nextSFAEdge:', nextSFAEdge, itemMapSet[nextSFAEdge])
            nextSFAEdgeValue = itemMapSet[nextSFAEdge]
            nextSFAEdgeValueVars = re.match(returnPattern, nextSFAEdgeValue, re.M | re.I)
            if nextSFAEdge in transitionChild[rightItem] or nextSFAEdgeValueVars and nextSFAEdgeValueVars.group(1) == itemMapSet[APIID]:
              newNextSFAEdges.add(nextSFAEdge)
          if newNextSFAEdges:
            compressedSAP[rightItem] = newNextSFAEdges

        # print('compressedSAP:', compressedSAP)
        # paths = []
        # for headSFAEdge in compressedSAP:
        #   for tailSFAEdge in compressedSAP[headSFAEdge]:
        #     paths.append((itemMapSet[headSFAEdge], itemMapSet[tailSFAEdge], ''))
        # PathDir = 'Path'
        # if os.path.exists(PathDir):
        #   shutil.rmtree(PathDir)
        # os.mkdir(PathDir)
        # drawRules(paths, os.path.join(PathDir, APIName + '_' + str(ruleID)))

        if not compressedSAP:
          with open(violatedFile, 'w') as file_write:
            print((ruleID, location), file = file_write)
            # print('no compressedSAP')
          continue

        (SAPNodes, SAPPaths) = getSAPPaths(startSAPNodeAddresses, SAP)
        if not SAPPaths:
          continue
        (compressedSAPNodes, compressedSAPPaths) = getSAPPaths(startSAPNodes, compressedSAP)
        if not compressedSAPPaths:
          continue
        print('Nodes:', len(SAPNodes), len(compressedSAPNodes), 'Paths:', len(SAPPaths), len(compressedSAPPaths))

        # translate(APIID, right, ruleID, SAPDir, compressedSAP, newAPNodes, location, startSAPNodes, violatedFile, callerLocation)
  
  return # 暂时放弃这块

  callerIDFile = {}
  for location in callerLocation:
    callerFile = locationMapSet[location][0]
    caller = locationMapSet[location][1]
    if caller not in itemReMapSet:
      # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
      #   print('finish', file = file_write)
      return
    callerID = itemReMapSet[caller]
    if not os.path.exists(os.path.join(SAPDir, str(callerID))):
      # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
      #   print('finish', file = file_write)
      return
    if callerID not in callerIDFile:
      callerIDFile[callerID] = set()
    callerIDFile[callerID].add(callerFile)
  
  for callerID in callerIDFile:
    with open(os.path.join(SAPDir, str(callerID)), 'r') as file_read:
      for line in file_read:
        line = line.strip()
        if line:
          itemSet = line.split(' | ')
          callerSAP = eval(itemSet[0])
          callerAPNodes = eval(itemSet[1])
          callerLocationID = int(itemSet[2])

          if locationMapSet[callerLocationID][0] not in callerIDFile[callerID]:
            continue
          for callerSAPNodeAddress in callerAPNodes:
            callerSAPEdges = callerAPNodes[callerSAPNodeAddress]
            if callerID in callerSAPEdges:
              visitedCallerSAPNodeAddresses = set()
              currCallerSAPNodeAddresses = []
              currCallerSAPNodeAddresses.append(callerSAPNodeAddress)
              while currCallerSAPNodeAddresses:
                currCallerSAPNodeAddress = currCallerSAPNodeAddresses.pop()

                if currCallerSAPNodeAddress in  visitedCallerSAPNodeAddresses:
                  continue
                visitedCallerSAPNodeAddresses.add(currCallerSAPNodeAddress)

                if currCallerSAPNodeAddress not in callerSAP: # 缺少对caller相关值的检查
                  with open(violatedFile, 'w') as file_write:
                    # print((ruleID, location, visitedEdgeValues), file = file_write)
                    # print('2')
                    location = locationReMapSet[locationMapSet[callerLocationID][0]][itemMapSet[callerID]]
                    print((ruleID, location), file = file_write)
                  # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
                  #   print('finish', file = file_write)
                  return
                
                for nextCallerSAPNodeAddress in callerSAP[currCallerSAPNodeAddress]:
                  nextCallerSAPEdges = callerAPNodes[nextCallerSAPNodeAddress]
                  hasCallerCheck = False
                  for nextCallerSAPEdge in nextCallerSAPEdges:
                    nextCallerSAPEdgeValue = itemMapSet[nextCallerSAPEdge]
                    nextCallerSAPEdgeVars = re.match(condPattern, nextCallerSAPEdgeValue, re.M | re.I)
                    if nextCallerSAPEdgeVars:
                      if nextCallerSAPEdgeVars.group(1) == caller:
                        hasCallerCheck = True
                        break
                    nextCallerSAPEdgeVars = re.match(returnPattern, nextCallerSAPEdgeValue, re.M | re.I)
                    if nextCallerSAPEdgeVars:
                      if nextCallerSAPEdgeVars.group(1) == caller:
                        hasCallerCheck = True
                        break

                  if hasCallerCheck:
                    continue
                
                  currCallerSAPNodeAddresses.append(nextCallerSAPNodeAddress)



def translate(APIID, right, ruleID, SAPDir, compressedSAP, APNodes, location, startSAPNodes, violatedFile, callerLocation):
  # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
  #   print('start', file = file_write)
  # print('right:', right)
  hasCheck = False # 用于标识是否存在对相关值的检查，如果存在，则caller的相关值也需要检查
  TranslateTime = time.time() # 限制每个文件的检测时间
  # startSAPNodeAddresses = getStarts(SAP, right)
  workList = []
  loopList = []
  successWorks = []
  memo = {}
  # for startSAPNodeAddress in startSAPNodeAddresses:
  #   workList.append((startSAPNodeAddress, '1', set(), False, []))
  for startSAPNode in startSAPNodes:
    workList.append((startSAPNode, '1', set(), False, []))
  # print('workList:', workList)
  while workList or loopList:
    usedTime = time.time() - TranslateTime
    if usedTime > 60:
      # print('Translate timeout')
      # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
      #   print('finish', file = file_write)
      return # 超时就不算漏洞了

    # 如果存在
    if not workList:
      work = loopList.pop()
      isSuccess = False
      for success in successWorks:
        if work[2].issubset(success):
          isSuccess = True
          break
      if isSuccess:
        continue
    else:
      work = workList.pop()
    # print('work:', work)
    currSAPNode = work[0]
    currSFANode = work[1]
    visitedNodes = work[2]
    hasAPI = work[3]
    visitedEdges = work[4]
    # for edges in visitedEdges:
    #   print('{', end = '')
    #   for edge in edges:
    #     print(itemMapSet[edge], end = ' ')
    #   print('}', end = ' ')
    # print()
    # print(currSAPNodeAddress)
    # if currSAPNodeAddress != 'F':
    #   print('currSAPEdges:', end = ' ')
    #   for currSAPEdge in APNodes[currSAPNodeAddress]:
    #     print(itemMapSet[currSAPEdge], end = ' ')
    #   print()

    if currSFANode not in right: # 该路径翻译成功
      successWorks.append(visitedNodes)
      continue

    if currSAPNode == 'F': # 路径结束节点
      if not hasAPI:
        continue
      # print('hasAPI')
      # 翻译失败
      # visitedEdgeValues = []

      # 对效率和准确性影响有点高，所以放弃
      # conditions = {}
      # isFeasible = True
      # for edges in visitedEdges:
      #   edgeValues = set()
      #   singleConditions = {} # 消除单独cmp带来的误报
      #   for edge in edges:
      #     edgeValue = itemMapSet[edge]
      #     edgeValues.add(edgeValue)
      #     edgeVars = re.match(condPattern, edgeValue, re.M | re.I)
      #     if edgeVars:
      #       variable = edgeVars.group(1) + '(' + edgeVars.group(2) + ')'
      #       predicate = predicateMap[edgeVars.group(3)]
      #       number = edgeVars.group(4)
      #       if variable not in singleConditions:
      #         singleConditions[variable] = {}
      #       if number not in singleConditions[variable]:
      #         singleConditions[variable][number] = set()
      #       singleConditions[variable][number].add(predicate)

      #   for variable in singleConditions:
      #     for number in singleConditions[variable]:
      #       for predicate in singleConditions[variable][number]:
      #         if not checkFeasibility(singleConditions[variable][number], predicate):
      #           continue
      #         if variable not in conditions:
      #           conditions[variable] = {}
      #         if number not in conditions[variable]:
      #           conditions[variable][number] = set()
      #         # print('visitedEdges:', visitedEdges)
      #         # print('predicate:', conditions[variable][number], predicate)
      #         if not checkFeasibility(conditions[variable][number], predicate): # 消除不可行路径
      #           # print(variable, predicate, number)
      #           # print('visitedEdges:', visitedEdgeValues)
      #           isFeasible = False
      #           break
      #         conditions[variable][number].add(predicate)

      #   if not isFeasible:
      #     break
      # if not isFeasible:
      #   # print('not feasible')
      #   continue
      # print('isFeasible')
      with open(violatedFile, 'w') as file_write:
        # print((ruleID, location, visitedEdgeValues), file = file_write)
        # print('1')
        print((ruleID, location), file = file_write)
      # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
      #   print('finish', file = file_write)
      return

    nextSFANode = currSFANode
    hasAPI = work[3]
    visitedEdges = copy.deepcopy(work[4])
    visitedEdges.append(currSAPNode)
    if currSAPNode == APIID:
      hasAPI = True
    # for currSAPEdge in currSAPEdges:
    usedTime = time.time() - TranslateTime
    if usedTime > 60:
      # print('Translate timeout')
      # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
      #   print('finish', file = file_write)
      return # 超时就不算漏洞了
    
    currSAPNodeValue = itemMapSet[currSAPNode]

    currSAPNodeVars = re.match(returnPattern, currSAPNodeValue, re.M | re.I) # return当作跨函数调用的标志，以减少误报
    if currSAPNodeVars:
      break

    if currSAPNode in right[currSFANode]:
      nextSFANode = right[currSFANode][currSAPNode]      
      currSAPNodeVars = re.match(condPattern, currSAPNodeValue, re.M | re.I)
      if currSAPNodeVars:
        hasCheck = True
    # elif itemMapSet[APIID] == 'EVP_MD_fetch' and itemMapSet[currSAPNode] == 'EVP_MD_free': # 新增一条额外规则减少误报
    #   nextSFANode = 'F'
      # break
    # else:
    #   currSAPNodeVars = re.match(returnPattern, currSAPNodeValue, re.M | re.I)
    #   if currSAPNodeVars:
    #     # print('currSAPNodeVars:', currSAPNodeVars.group(1), currSAPNodeVars.group(2))
    #     hasSFA = False
    #     for SFAEdge in right[currSFANode]:
    #       usedTime = time.time() - TranslateTime
    #       if usedTime > 60:
    #         # print('Translate timeout')
    #         # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
    #         #   print('finish', file = file_write)
    #         return # 超时就不算漏洞了

    #       SFAEdgeValue = itemMapSet[SFAEdge]
    #       SFAEdgeVars = re.match(condPattern, SFAEdgeValue, re.M | re.I)
    #       if SFAEdgeVars:
    #         # print('SFAEdgeVars:', SFAEdgeVars.group(1), SFAEdgeVars.group(2))
    #         if SFAEdgeVars.group(1) == currSAPNodeVars.group(1) and  SFAEdgeVars.group(2) == currSAPNodeVars.group(2):
    #           # print('true')
    #           nextSFANode = right[currSFANode][SFAEdge]
    #           hasCheck = True
    #           hasSFA = True
    #           break
    #     if hasSFA:
    #       break

    
    if currSAPNode not in memo:
      memo[currSAPNode] = set()

    # 由于不可行路径的存在，可能会舍弃掉
    if nextSFANode in memo[currSAPNode]: # 在同一个上下文下访问过该节点，所以停止
      loopList.append(('F', nextSFANode, copy.deepcopy(visitedNodes), hasAPI, visitedEdges))
      continue
    memo[currSAPNode].add(nextSFANode)

    # 和不可行路径绑定
    # if str(visitedNodeAddresses) in memo[currSAPNodeAddress]:
    #   loopList.append(('F', nextSFANode, copy.deepcopy(visitedNodeAddresses), hasAPI, visitedEdges))
    #   continue
    # memo[currSAPNodeAddress].add(str(visitedNodeAddresses))

    visitedNodes.add(currSAPNode)

    if currSAPNode not in compressedSAP or not compressedSAP[currSAPNode]:
      workList.append(('F', nextSFANode, copy.deepcopy(visitedNodes), hasAPI, visitedEdges))
    else:
      for nextSAPNode in compressedSAP[currSAPNode]:
        workList.append((nextSAPNode, nextSFANode, copy.deepcopy(visitedNodes), hasAPI, visitedEdges))
  # print('finish work')
  # 所有路径翻译成功
  # hasCheck = False # 暂时禁用
  if hasCheck:
    callerLocation.add(location)
    
  # with open(os.path.join('translate', str(lineNo)), 'w') as file_write:
  #   print('finish', file = file_write)
  return



# def translate(path, right, hasReturn = False):
#   currentNode = '1'
#   pathCur = 0
#   # isChanged = False
#   while pathCur < len(path) and currentNode in right:
#     # currentOperation = str(path[pathCur])
#     currentOperation = path[pathCur]
#     if currentOperation in right[currentNode]:
#       # isChanged = True
#       currentNode = right[currentNode][currentOperation]
#       if currentNode == 'F': # SFA执行到了final节点
#         return True
#     elif hasReturn: # RETURN之后path应该就到头了，所以就不再继续看了，碰到特殊情况再修改
#       currentOperationValue = itemMapSet[currentOperation]
#       if currentOperationValue.startswith('RETURN '):
#         currentVar = currentOperationValue[7:]
#         for rightOperation in right[currentNode]:
#           rightOperationValue = itemMapSet[rightOperation]
#           rightVars = rightOperationValue.split(' ')
#           if len(rightVars) == 3:
#             if rightVars[0] == currentVar:
#               if right[currentNode][rightOperation] == 'F': # SFA执行到了final节点
#                 return True
#     pathCur += 1
#     # if isChanged and pathCur == len(path):
#     #   pathCur = 0
#     #   isChanged = False
#   return False


def violationCombine():
  cur.execute('drop table if exists Violations')
  cur.execute('create table if not exists Violations(ID integer primary key autoincrement, Rule integer not null, Locations string not null)')
  violationDir = os.path.join(outputDir, 'Violation')
  violations = {}
  for root, dirs, files in os.walk(violationDir):
    for file in files:
      if file.isdigit():
        violatedFile = os.path.join(root, file)
        with open(violatedFile, 'r') as file_read:
          for line in file_read:
            line = line.strip()
            if line:
              violation = eval(line)
              ruleID = violation[0]
              location = violation[1]
              # visitedEdgeValues = violation[2]
              if ruleID not in violations:
                # violations[ruleID] = {}
                violations[ruleID] = set()
              violations[ruleID].add(location)
              # if location not in violations[ruleID]:
              #   violations[ruleID][location] = set()
              # violations[ruleID][location].add(str(visitedEdgeValues))
  for ruleID in violations:
    cur.execute('insert into Violations(Rule, Locations) values(?, ?)', (ruleID, str(violations[ruleID])))
  conn.commit()
  shutil.rmtree(violationDir)


def outputRules(outputDir):
  # ruleDir = os.path.join(outputDir, 'Rules')
  # if os.path.exists(ruleDir):
  #   shutil.rmtree(ruleDir)
  # os.mkdir(ruleDir) 
  # cur.execute('select Left, Right, Support, Location from Rules order by Support desc')
  cur.execute('select ID, API, Right, RightItems, Support, Locations from Rules')
  rules = cur.fetchall()
  with open(os.path.join(outputDir, 'Rules'), 'w') as file_write:
    for rule in rules:
      ID = rule[0]
      API = itemMapSet[rule[1]]

      flag = False
      if appName in notBugAPIPatterns:
        for notBugPattern in notBugAPIPatterns[appName]:
          if notBugPattern in API:
            flag = True
            break
        if flag:
          continue

      if appName in notBugAPIs and API in notBugAPIs[appName]:
        continue

      right = {}
      for headNode in eval(rule[2]):
        if headNode not in right:
          right[headNode] = {}
        for transition in eval(rule[2])[headNode]:
          transitionValue = itemMapSet[transition]
          right[headNode][transitionValue] = eval(rule[2])[headNode][transition]

      flag = False
      rightItems = set()
      for edge in eval(rule[3]):
        if 'CMP' in itemMapSet[edge]:
          flag = True
        rightItems.add(itemMapSet[edge])
      if not flag:
        continue

      support = rule[4]
      location = list(eval(rule[5]))
      if not location:
        continue
      ruleLocation = locationMapSet[location[0]]
      # queryIDSet(eval(rule[4]), 'Locations')[0]
      print('------------------------------------------', file = file_write)
      print('ID:', ID, file = file_write)
      print('API:', API, file = file_write)
      print('Right:', right, file = file_write)
      print('RightItems:', rightItems, file = file_write)
      print('Support:', support, file = file_write)
      print('ruleLocation:', ruleLocation[0], ruleLocation[1], file = file_write)
      print('------------------------------------------', file = file_write)
    

def outputViolations(outputDir):
  cur.execute('select Rules.ID, Rules.API, Rules.RightItems, Rules.Support, Rules.Locations, Violations.Locations from Rules, Violations where Rules.ID = Violations.Rule order by Rules.Support desc, Rules.Right asc')
  violations = cur.fetchall()
  # with open(os.path.join(outputDir, 'Violations'), 'w') as file_write:
  with open('Violations', 'w') as file_write:
    for violation in violations:
      ruleID = violation[0]
      API = itemMapSet[violation[1]]
      # if API != 'clk_enable':
      #   continue

      flag = False
      if appName in notBugAPIPatterns:
        for notBugPattern in notBugAPIPatterns[appName]:
          if notBugPattern in API:
            flag = True
            break
        if flag:
          continue

      if appName in notBugAPIs and API in notBugAPIs[appName]:
        continue

      flag = False
      right = set()
      for edge in eval(violation[2]):
        if 'CMP' in itemMapSet[edge]:
          flag = True
        right.add(itemMapSet[edge])
      if not flag:
        continue

      support = violation[3]

      if eval(violation[4]):
        ruleLocation = locationMapSet[list(eval(violation[4]))[0]]
      else:
        ruleLocation = ('', '')
      # violationLocations = []
      violationLocations = set()
      for locationID in eval(violation[5]):
        # violatedPathStr = eval(violation[5])[locationID]
        location = locationMapSet[locationID]
        # violatedPath = []
        # for edges in violatedPathID:
        #   edgesStr = set()
        #   for edge in edges:
        #     edgesStr.add(itemMapSet[edge])
        #   # edgesStr = queryIDSet(edges, 'Items')
        #   violatedPath.append(edgesStr)
        # violationLocations.append((location[0], location[1], violatedPathStr))
        # if location[0] != 'drivers/media/platform/samsung/s3c-camif/camif-core.c':
        #   continue
        # print(location[0])

        if location[0].startswith('samples/') or location[0].startswith('demos/') or location[0].startswith('lib/') or 'lkdtm' in location[0].split('/') or 'test' in location[0].split('/') or 'tests' in location[0].split('/') or 'selftests' in location[0].split('/') or 'unittest.c' in location[0].split('/'):
          continue
        if appName in notBugFunctions and location[1] in notBugFunctions[appName]:
          continue

        # violationLocations.append((location[0], location[1]))
        violationLocations.add(location[0])
      if not violationLocations:
        continue

      violationLocationList = sorted(violationLocations)

      # lastViolationLocation = ''
      # newViolationLocationList = []
      # for violationLocation in violationLocationList:
      #   # violationLocation = os.path.normpath(os.path.abspath(violationLocation))
      #   # if lastViolationLocation == 'drivers/nvdimm/dax_devs.c' and violationLocation == 'drivers/nvdimm/pfn_devs.c':
      #   #   print(os.path.dirname(lastViolationLocation), os.path.dirname(violationLocation))
      #   if os.path.dirname(lastViolationLocation) == os.path.dirname(violationLocation): # 属于同一个目录
      #     newViolationLocationList[len(newViolationLocationList) - 1].add(violationLocation)
      #   else:
      #     newViolationLocationList.append({violationLocation})
      #   lastViolationLocation = violationLocation
      # violationLocationList = newViolationLocationList


      # violationLocations.sort(key = lambda element : element[0] + element[1])
      # print(API, right, support, ruleLocation[0], ruleLocation[1], ruleID, violationLocations[0][0], violationLocations[0][1], sep = '&', file = file_write)
      print(API, right, support, ruleLocation[0], ruleLocation[1], ruleID, violationLocationList[0], sep = '&', file = file_write)
      for i in range(1, len(violationLocationList)):
        print(API, '', '', '', '', '', violationLocationList[i], sep = '&', file = file_write)
      # print('------------------------------------------', file = file_write)
      # print('Left:', left, file = file_write)
      # print('Right:', right, file = file_write)
      # print('Support:', support, file = file_write)
      # print('ruleLocation:', ruleLocation, file = file_write)
      # print('itemSetLocation:', itemSetLocation, file = file_write)
      # print('------------------------------------------', file = file_write)


def test(fileName):
  with open(fileName, 'r') as file_read:
    for line in file_read:
      print(line)


if __name__ == '__main__':
  parser = ArgumentParser()
  parser.add_argument('-s', '--step', type = str, required = True)
  parser.add_argument('-c', '--continuous', type = bool, default = False)
  parser.add_argument('-d', '--database', type = str, required = True)
  parser.add_argument('-a', '--app', type = str, required = True)
  parser.add_argument('-i', '--inputDir', type = str)
  parser.add_argument('-o', '--outputDir', type = str)
  parser.add_argument('--debug', type = str, required = False)
  
  args = parser.parse_args()
  step = args.step
  continuous = args.continuous
  debug = args.debug
  appName = args.app
  database = appName + args.database
  SAPDir = appName + 'SAP'
  # outputDir = os.path.join(args.outputDir, appName)
  outputDir = args.outputDir
  if not outputDir:
    print('No outputDir')
    exit(1)

  conn = sqlite3.connect(database)
  cur = conn.cursor()

  # if step == 'GetInput':
  #   inputDir = args.inputDir
  #   if not inputDir:
  #     print('No inputDir')
  #     exit(1)

  #   cwd = os.getcwd()
  #   os.chdir(app)
  #   if appName == 'openssl':
  #     os.system('export LLVM_COMPILER=clang')
  #     os.system('export WLLVM_BC_STORE=/home/SVF-tools/SVF/SVF-example/SFAInput/')
  #     os.system('rm -rf ' + os.path.join(inputDir, '*'))
  #     os.system('make clean')
  #     os.system('CC=wllvm ./Configure enable-demos')
  #     os.system('make -j48')
  #   # elif appName == 'linux':
  #     # os.system('make mrproper')
  #     # make CC=clang defconfig # 默认配置
  #     # make CC=clang menuconfig -> General setup -> 取消勾选'compile the kernel with warnings as errors' -> esc退出保存
  #     # make CC=wllvm LLVM=1 -j48 #开始编译
  #     # extract-bc vmlinux #提取bitcode
  #   os.chdir(cwd)

  #   for root, dirs, files in os.walk(inputDir):
  #     for file in files:
  #       if not file.endswith('.bc'):
  #         continue
  #       input = os.path.join(root, file)
  #       cmd = ['opt', '-S', '-p=mem2reg', input, '-o', input] # 覆盖原文件
  #       subprocess.call(cmd)
  #   if continuous:
  #     step = 'SymbolicAPIPathGenerator'

  if step == 'SymbolicAPIPathGenerator':
    # print(step)
    start = time.time()
    inputDir = args.inputDir
    if not inputDir:
      print('No inputDir')
      exit(1)

    if os.path.exists(outputDir):
      shutil.rmtree(outputDir)
    os.makedirs(outputDir)

    if os.path.exists(SAPDir):
      shutil.rmtree(SAPDir)
    os.makedirs(SAPDir)

    inputFiles = []
    for root, dirs, files in os.walk(inputDir):
      for file in files:
        if not file.endswith('.bc'):
          continue
        inputFile = os.path.join(root, file)
        # create table timeoutSAP(ID integer primary key autoincrement, File string not null);
        cur.execute('select ID from timeoutSAP where File = ?', (inputFile, ))
        ID = cur.fetchone()
        if ID:
          continue
        inputFiles.append(inputFile)

    cur.execute('drop table if exists Items')
    cur.execute('drop table if exists Locations')
    # cur.execute('drop table if exists ItemSets')

    cur.execute('create table if not exists Items(ID integer primary key autoincrement, Value string not null)')
    cur.execute('create table if not exists Locations(ID integer primary key autoincrement, File string not null, Function string not null)')
    # cur.execute('create table if not exists ItemSets(ID integer primary key autoincrement, SAP string not null, APNodes string not null, API integer not null, Location integer not null)')

    processTotal = len(inputFiles)
    processCount = 0
    splitTimes = 100
    oneTime = int(processTotal / splitTimes)

    locationTable = {}
    itemsTable = {}
    locationTableID = 0
    itemsTableID = 0
    finishedFiles = 0

    for i in range(splitTimes):
      pool = multiprocessing.Pool(PROCESSOR)
      if i == splitTimes - 1:
        for j in range(i * oneTime, processTotal):
          input = inputFiles[j]
          # SymbolicExecutor(input, outputDir)
          pool.apply_async(SymbolicExecutor, args=(input, outputDir), callback = collectMyResult)
      else:
        for j in range(i * oneTime, (i + 1) * oneTime):
          input = inputFiles[j]
          # SymbolicExecutor(input, outputDir)
          pool.apply_async(SymbolicExecutor, args=(input, outputDir), callback = collectMyResult)
      pool.close()
      pool.join()
      IndexBuilder(outputDir, SAPDir, locationTable, itemsTable, finishedFiles)

    for fileName in locationTable:
      for function in locationTable[fileName]:
        locationID = locationTable[fileName][function]
        cur.execute('insert into Locations(ID, File, Function) values(?, ?, ?)', (locationID, fileName, function))

    for value in itemsTable:
      valueID = itemsTable[value]
      cur.execute('insert into Items(ID, Value) values(?, ?)', (valueID, value))

    conn.commit()

    if continuous:
      step = 'FrequentSubgraphMiner'

  itemMapSet = {}
  itemReMapSet = {}
  cur.execute('select ID, Value from Items')
  for item in cur.fetchall():
    itemMapSet[item[0]] = item[1]
    itemReMapSet[item[1]] = item[0]
  locationMapSet = {}
  locationReMapSet = {}
  cur.execute('select ID, File, Function from Locations')
  for item in cur.fetchall():
    locationMapSet[item[0]] = (item[1], item[2])
    if item[1] not in locationReMapSet:
      locationReMapSet[item[1]] = {}
    locationReMapSet[item[1]][item[2]] = item[0]


  if step == 'FrequentSubgraphMiner': # 有些超时还是没有解决
    # print(step)
    start = time.time()

    SFADir = os.path.join(outputDir, 'SFA')
    DBDir = os.path.join(SFADir, 'DB')
    SFAInputDir = os.path.join(SFADir, 'input')
    SFAOutputDir = os.path.join(SFADir, 'output')
    if os.path.exists(SFADir):
      shutil.rmtree(SFADir)
    os.mkdir(SFADir)
    os.mkdir(DBDir)
    os.mkdir(SFAInputDir)
    os.mkdir(SFAOutputDir)

    if os.path.exists('Rule'):
      shutil.rmtree('Rule')
    os.mkdir('Rule')

    cur.execute('select max(ID) from Items')
    itemLength = cur.fetchone()[0] + 1
    cur.execute('select max(ID) from Locations')
    locationLength = cur.fetchone()[0] + 1
    pool = multiprocessing.Pool(PROCESSOR)
    cur.execute('select ID, Value from Items where Value not like "% %"')
    APIs = cur.fetchall()
    processCount = 0
    processTotal = len(APIs)
    # processTotal = len(linuxAPI)
    for API in APIs:
      APIID = API[0]
      if not os.path.exists(os.path.join(SAPDir, str(APIID))):
        continue
      APIName = API[1]
      if appName in debugAPI and APIName in debugAPI[appName]:
        collectMyResult()
        continue
      # if APIID != 24045:
      #   continue
      # if APIName in linuxTimeoutAPI:
      #   continue
      # if APIName != 'EVP_MD_CTX_new':
      #   continue
      # print(APIName)
      # create table timeoutFSM(ID integer primary key autoincrement, API string not null);
      cur.execute('select ID from timeoutFSM where API = ?', (APIName, ))
      ID = cur.fetchone()
      if ID:
        collectMyResult()
        continue
      # cur.execute('select SAP, APNodes, Location from ItemSets where API = ?', (APIID, ))
      # itemSets = cur.fetchall()
      SFAInputFile = os.path.join(SFAInputDir, APIName)
      SFAOutputFile = os.path.join(SFAOutputDir, APIName)
      pool.apply_async(FrequentSubgraphMiner, args=(APIID, APIName, DBDir, SFAInputFile, SFAOutputFile), callback = collectMyResult)
      # FrequentSubgraphMiner(APIID, APIName, DBDir, SFAInputFile, SFAOutputFile)
    pool.close()
    pool.join()
    print()
    end = time.time()
    print(step, 'Execution time:', end - start)
    if continuous:
      step = 'SFACombine'

  if step == 'SFACombine':
    # print(step)
    start = time.time()

    SFACombine()
    end = time.time()
    print(step, 'Execution time:', end - start)
    if continuous:
      step = 'Translator'

  if step == 'Translator':
    start = time.time()

    violationDir = os.path.join(outputDir, 'Violation')
    if os.path.exists(violationDir):
      shutil.rmtree(violationDir)
    os.mkdir(violationDir)
    cur.execute('select ID, API, Right, RightItems from Rules')
    rules = cur.fetchall()

    pool = multiprocessing.Pool(PROCESSOR)
    processCount = 0
    processTotal = len(rules)

    for rule in rules:
      ruleID = rule[0]
      # if rule[0] != 923:
      #   continue
      APIID = int(rule[1])
      APIName = itemMapSet[APIID]
      if APIName not in {'devm_kmalloc', '__kmalloc', 'kmalloc_trace', 'kmalloc_array', 'clk_prepare', 'clk_enable', 'platform_get_irq', '__devm_add_action', 'kmemdup', 'ioremap'}:
        continue
      print(APIName)
      right = eval(rule[2])
      edgeCount = 0
      for node1 in right:
        edgeCount += len(right[node1])
      if edgeCount <= 1:
        collectMyResult()
        continue
      rightItems = eval(rule[3])
      violatedAPIDir = os.path.join(violationDir, str(APIID))
      os.mkdir(violatedAPIDir)
      # pool.apply_async(Translator, args=(APIID, right, rightItems, ruleID, SAPDir, violatedAPIDir), callback = collectMyResult)
      Translator(APIID, right, rightItems, ruleID, SAPDir, violatedAPIDir)

    pool.close()
    pool.join()
    print()
    # conn.commit()
    end = time.time()
    print(step, 'Execution time:', end - start)
    if continuous:
      step = 'violationCombine'

  if step == 'violationCombine':
    # print(step)
    start = time.time()

    violationCombine()
    end = time.time()
    print(step, 'Execution time:', end - start)
    if continuous:
      step = 'outputRules'
  
  if step == 'outputRules':
    # print(step)
    start = time.time()

    outputRules(outputDir)
    end = time.time()
    print(step, 'Execution time:', end - start)
    if continuous:
      step = 'outputViolations'

  if step == 'outputViolations':
    # print(step)
    start = time.time()

    outputViolations(outputDir)
    end = time.time()
    print(step, 'Execution time:', end - start)
    if continuous:
      step = 'drawRules'

  if step == 'drawRules':
    start = time.time()
    RuleDir = 'RuleGraph'
    if os.path.exists(RuleDir):
      shutil.rmtree(RuleDir)
    os.mkdir(RuleDir)

    cur.execute('select ID, API, Right from Rules')
    rules = cur.fetchall()

    for rule in rules:
      ruleID = rule[0]
      APIID = rule[1]
      APIName = itemMapSet[APIID]
      # if APIName != 'mutex_lzock_nested':
      #   continue

      if appName in notBugAPIPatterns:
        flag = False
        for notBugPattern in notBugAPIPatterns[appName]:
          if notBugPattern in APIName:
            flag = True
            break
        if flag:
          continue

      if appName in notBugAPIs and APIName in notBugAPIs[appName]:
        continue

      SFA = eval(rule[2])
      paths = []
      for node1 in SFA:
        for edge in SFA[node1]:
          node2 = SFA[node1][edge]
          paths.append((node1, node2, edge))
      drawRules(paths, os.path.join(RuleDir, APIName + '_' + str(ruleID)))
    
    end = time.time()
    print(step, 'Execution time:', end - start)

  if step == 'drawPaths':
    PathDir = 'Path'
    if os.path.exists(PathDir):
      shutil.rmtree(PathDir)
    os.mkdir(PathDir)

    APIName = 'avformat_write_header'
    file = 'libavformat/webm_chunk.c'
    function = 'webm_chunk_write_header'

    cur.execute('select ID from Items where Value = ?', (APIName, ))
    APIID = cur.fetchone()[0]
    cur.execute('select ID from Locations where File = ? and Function = ?', (file, function))
    locationID = cur.fetchone()[0]

    itemSets = []
    with open(os.path.join(SAPDir, str(APIID)), 'r') as file_read:
      lineNo = 0
      for line in file_read:
        lineNo += 1
        line = line.strip()
        if line:
          itemSet = line.split(' | ')
          if itemSet[2] == str(locationID):
            itemSets.append((lineNo, itemSet[0], itemSet[1]))

    # cur.execute('select ItemSets.ID, ItemSets.SAP, ItemSets.APNodes from ItemSets, Items, Locations where ItemSets.API = Items.ID and ItemSets.Location = Locations.ID and Items.Value = 'EVP_MD_fetch' and Locations.File = 'crypto/pkcs12/p12_mutl.c' and Locations.Function = 'pkcs12_gen_mac' ')
    # # cur.execute('select Edges from ItemSets where ID = 50943')
    # itemSets = cur.fetchall()

    for itemSet in itemSets:
      ID = itemSet[0]
      SAP = eval(itemSet[1])
      APNodes = eval(itemSet[2])
      print(SAP)

      drawPaths(SAP, APNodes, os.path.join(PathDir, 'Path' + str(ID)))

  if step == 'test':
    print(step)
    # original_linux = {}
    # new_linux = []
    # with open('original_linux', 'r') as file_read:
    #   for line in file_read:
    #     item = line.strip().split('\t')
    #     API = item[0]
    #     violationFile = item[6]
    #     result = item[7] if len(item) > 7 else ''
    #     date = item[8] if len(item) > 8 else ''
    #     commit = item[9] if len(item) > 9 else ''

    #     if API not in original_linux:
    #       original_linux[API] = {}
    #     original_linux[API][violationFile] = result + '&' + date + '&' + commit

    # with open('new_linux_result', 'w') as file_write:
    #   with open('new_linux', 'r') as file_read:
    #     for line in file_read:
    #       item = line.strip().split('\t')
    #       API = item[0]
    #       violationFile = item[6]
    #       if API in original_linux and violationFile in original_linux[API]:
    #         print(item[0], item[1], item[2], item[3], item[4], item[5], item[6], original_linux[API][violationFile], sep = '&', file = file_write)
    #       else:
    #         print(item[0], item[1], item[2], item[3], item[4], item[5], item[6], sep = '&', file = file_write)
    
    cur.execute('select ID from Items where Value not like "% %"')
    APIs = cur.fetchall()
    SAPCount = 0
    APICount = 0
    # processTotal = len(linuxAPI)
    for API in APIs:
      APIID = API[0]
      if not os.path.exists(os.path.join(SAPDir, str(APIID))):
        continue
      APICount += 1
      with open(os.path.join(SAPDir, str(APIID)), 'r') as file_read:
        for line in file_read:
          line = line.strip()
          if line:
            SAPCount += 1
    print('APICount:', APICount)
    print('SAPCount:', SAPCount)

  if step == 'benchmark':
    openssl_result = {}
    with open('OpenSSL_result', 'r') as file_read:
      for line in file_read:
        line = line.strip()
        if line:
          item = line.split('	')
          API = item[0]
          location = item[1]
          if API not in openssl_result:
            openssl_result[API] = set()
          openssl_result[API].add(location)
    with open('Benchmark', 'r') as file_read:
      for line in file_read:
        line = line.strip()
        if line:
          item = line.split('	')
          API = item[0]
          location = item[1]
          if API in openssl_result and location in openssl_result[API]:
            print('TRUE')
          else:
            print('FALSE')
        
    # pool = multiprocessing.Pool(PROCESSOR)
    # fileName = '/home/SVF-tools/SVF/SVF-example/test.c'
    # for i in range(20):
    #   pool.apply_async(test, args=(fileName, ))
    # pool.close()
    # pool.join()

  if step == 'OpenSSLTranslator':
    start = time.time()

    violationDir = os.path.join(outputDir, 'Violation')
    if os.path.exists(violationDir):
      shutil.rmtree(violationDir)
    os.mkdir(violationDir)

    ruleConn = sqlite3.connect('opensslSFA.db')
    ruleCur = ruleConn.cursor()
    
    ruleCur.execute('select ID, API, Right, RightItems from Rules')
    rules = ruleCur.fetchall()
    
    ruleItemIndex = len(itemReMapSet)
    if ruleItemIndex in itemReMapSet:
      print('error index')
      exit(1)
    ruleItemMapSet = {}
    ruleCur.execute('select ID, Value from Items')
    for ruleItem in ruleCur.fetchall():
      if ruleItem[1] in itemReMapSet:
        ruleItemMapSet[ruleItem[0]] = itemReMapSet[ruleItem[1]]
      else:  
        ruleItemMapSet[ruleItem[0]] = ruleItemIndex

    pool = multiprocessing.Pool(PROCESSOR)
    processCount = 0
    processTotal = len(rules)

    for rule in rules:
      ruleID = rule[0]
      # if rule[0] != 923:
      #   continue
      APIID = ruleItemMapSet[int(rule[1])]
      if not os.path.exists(os.path.join(SAPDir, str(APIID))):
        continue

      APIName = itemMapSet[APIID]
      # if APIName != 'X509_STORE_CTX_new':
      #   continue
      # print(APIName)
      ruleRight = eval(rule[2])
      right = {}
      for node1 in ruleRight:
        right[node1] = {}
        for item in ruleRight[node1]:
          right[node1][ruleItemMapSet[item]] = ruleRight[node1][item]

      edgeCount = 0
      for node1 in right:
        edgeCount += len(right[node1])
      if edgeCount <= 1:
        collectMyResult()
        continue

      ruleRightItems = eval(rule[3])
      rightItems = set()
      for ruleRightItem in ruleRightItems:
        rightItems.add(ruleItemMapSet[ruleRightItem])

      violatedAPIDir = os.path.join(violationDir, str(APIID))
      os.mkdir(violatedAPIDir)
      pool.apply_async(Translator, args=(APIID, right, rightItems, ruleID, SAPDir, violatedAPIDir), callback = collectMyResult)
      # Translator(APIID, right, rightItems, ruleID, SAPDir, violatedAPIDir)

    pool.close()
    pool.join()
    print()
    # conn.commit()

    violationCombine()

    cur.execute('select Rule, Locations from Violations')
    violations = cur.fetchall()
    with open('Violations', 'w') as file_write:
      for violation in violations:
        ruleID = violation[0]
        violationLocations = set()
        for locationID in eval(violation[1]):
          location = locationMapSet[locationID]

          if location[0].startswith('test/') or location[0].startswith('samples/') or location[0].startswith('demos/') or location[0].startswith('lib/'):
            continue
          if appName in notBugFunctions and location[1] in notBugFunctions[appName]:
            continue

          violationLocations.add(location[0])
        if not violationLocations:
          continue
        violationLocationList = sorted(violationLocations)

        ruleCur.execute('select API, RightItems, Support, Locations from Rules where ID = ?', (ruleID,))
        rule = ruleCur.fetchone()
        API = itemMapSet[ruleItemMapSet[rule[0]]]
        # if API != 'X509_STORE_CTX_new':
        #   continue

        flag = False
        if 'openssl' in notBugAPIPatterns:
          for notBugPattern in notBugAPIPatterns['openssl']:
            if notBugPattern in API:
              flag = True
              break
          if flag:
            continue

        if 'openssl' in notBugAPIs and API in notBugAPIs['openssl']:
          continue

        right = set()
        for edge in eval(rule[1]):
          ruleCur.execute('select Value from Items where ID = ?', (edge, ))
          edgeValue = ruleCur.fetchone()[0]
          if 'CMP' in edgeValue:
            flag = True
          right.add(edgeValue)
        if not flag:
          continue

        support = rule[2]
        # ruleLocation = locationMapSet[list(eval(rule[3]))[0]]
        ruleLocation = ('', '')
        
        print(API, right, support, ruleLocation[0], ruleLocation[1], ruleID, violationLocationList[0], sep = '&', file = file_write)
        for i in range(1, len(violationLocations)):
          print(API, '', '', '', '', '', violationLocationList[i], sep = '&', file = file_write)

    ruleCur.close()
    ruleConn.close()

    end = time.time()
    print(step, 'Execution time:', end - start)

  cur.close()
  conn.close()
      
# /home/SVF-tools/SVF/SVF-example/src/svf-example -stat=false -extapi=/home/SVF-tools/SVF/node_modules/SVF/Release-build/lib/extapi.bc openssl.ll
# python3 SFAMiner.py -s=test -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=ffmpeg
# python3 SFAMiner.py -s=benchmark -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=ffmpeg

# tmux attach
# python3 SFAMiner.py -s=drawPaths -o=graphviz/ -d=SFA.db
# wpa -ander -svfg -dump-vfg -opt-svfg=false -stat=false -extapi=/home/SVF-tools/SVF/node_modules/SVF/Release-build/lib/extapi.bc swap.ll
# wpa -type -dump-icfg -stat=false -extapi=/home/SVF-tools/SVF/node_modules/SVF/Release-build/lib/extapi.bc swap.ll
# wpa -ander -dump-callgraph -stat=false -extapi=/home/SVF-tools/SVF/node_modules/SVF/Release-build/lib/extapi.bc swap.ll

# opt-13 -dot-cfg .bc
# dot -Tpdf .dot -o .pdf
# dot -Tpng .dot -o .png





# python3 SFAMiner.py -s=GetInput -d=SFA.db -i=/home/SVF-tools/SVF/SVF-example/SFAInput -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=SymbolicAPIPathGenerator -d=SFA.db -i=/home/SVF-tools/SVF/share/deadline/code/bcfs/linux -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=FrequentSubgraphMiner -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=SFACombine -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=Translator -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=violationCombine -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=outputRules -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=outputViolations -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=drawRules -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=drawPaths -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=linux
# python3 SFAMiner.py -s=OpenSSLTranslator -d=SFA.db -o=/home/SVF-tools/SVF/SVF-example/SFAOutput -a=httpd