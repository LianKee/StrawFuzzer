#!env python3
import sys
import os
import re
import json

import click

import client
from client import load_summary, L

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG = client.load_config()
SUMMARY = client.load_summary()

# sys.path.append(os.path.realpath(os.path.join(SCRIPT_PATH)))

@click.group()
def cli():
    pass


@cli.command()
@click.option('--detailed', is_flag=True, help='Whether print detialed information')
def crashed(detailed):
    summary = SUMMARY
    count = 0
    for k, v in summary.items():
        if v['crashed']:
            if not detailed:
                L.lprint("[{}] {}".format(count, k))
            else:
                L.lprint("[{}] {} {}".format(count, k, v))
            count += 1

@cli.command()
def all_pairs():
    summary = SUMMARY
    count = 0
    for k, v in summary.items():
        print_potential(v, count, k)
        count += 1


@cli.command()
def failed():
    static_info = client.load_all_static_info()
    L.lprint("There are {} entries".format(len(static_info)))
    succes_items = set(map(lambda v: (v['entry'], v['risky']), SUMMARY.values()))
    L.lprint("There are {} recorded entries".format(len(succes_items)))
    count = 0
    skip_count = 0
    for entry_item in static_info:
        entrySignature = entry_item['signature']
        for risky_item in entry_item['riskyMethods']:
            riskySignature = risky_item['signature']
            pair = (entrySignature, riskySignature)
            if pair in succes_items:
                pass
            elif is_skipped(pair):
                skip_count += 1
            else:
                L.lprint("[{}] {}".format(count, pair))
                count += 1
    L.lprint("[*] Skipped {} not runned pairs".format(skip_count))

@cli.command()
@click.option("--no-lingress", is_flag=True, help="Don't use lingress for potential predicate")
def potential(no_lingress):
    summary = SUMMARY
    count = 0
    for k, v in summary.items():
        crashed = v['crashed']
        if crashed:
            continue
        if client.is_potential(v, use_lingress=not no_lingress):
            print_potential(v, count, k)
            count += 1


@cli.command()
@click.option('--expanded', is_flag=True, help='Whether print expanded information')
def report(expanded):
    summary = SUMMARY
    C = {}
    HC = {}
    P = {}
    HP = {}
    for k, v in summary.items():
        c = v['crashed']
        p = client.is_potential(v)
        hit = v['exploitationCount'] > client.get_sum_score(v) / 10
        if c and not hit:
            L.lprint("[{}] {}".format('C', k))
        elif c:
            risky = v['risky']
            if risky in HC:
                HC[risky].append(v)
            else:
                HC[risky] = [v]
        elif p:
            mark = 'P' if not hit else 'HP'
            print_potential(v, mark, k)
    count = 0
    L.lprint("-" * 20 + " Risky Methods " + "-" * 20)
    for risky, details in HC.items():
        if expanded:
            L.lprint("[{}] {}".format(count, risky))
            for subcount, entry in enumerate(map(lambda v: v['entry'], details)):
                L.lprint(" " * 4 + "({}) {}".format(subcount, entry))
        else:
            L.lprint("[{}] {} with {} entries".format(count, risky, len(details)))
        count += 1


@cli.command()
@click.argument('dst', nargs=1)
@click.argument('src', nargs=-1)
def merge(dst, src):
    dst_summary = {}
    for summary_path in src:
        with open(summary_path, 'r') as f:
            summary = json.load(f)
            for k, v in summary.items():
                if k in dst_summary:
                    L.lprint("[!] Warning {} is duplicated".format(k))
                dst_summary[k] = v
    with open(dst, 'w+') as f:
        json.dump(dst_summary, f)


@cli.command()
@click.argument('target')
@click.option('-i', "--info", is_flag=True, help="See static info")
@click.option('-c', "--compact", is_flag=True, help="Use compact mode")
def see(target, info, compact):
    signatures, _ = client.parse_signatures(target)
    pair = [None, None]
    if len(signatures) >= 2:
        pair = tuple(signatures[:2])
    elif len(signatures) == 1:
        signature = signatures[0]
        if '$Stub$Proxy' in signature:
            pair[0] = signature
        else:
            pair[1] = signature
    else:
        L.lprint('[-] Invalid input')
        return
    summary = SUMMARY
    for item in summary.values():
        if (not pair[0] or fuzzy_convert(item['entry']) == fuzzy_convert(pair[0])) and \
            (not pair[1] or fuzzy_convert(item['risky']) == fuzzy_convert(pair[1])):
            compact_dumps_print(item)
    if info:
        static_infos = client.load_all_static_info()
        for static_info in static_infos:
            if (not pair[0] or fuzzy_convert(static_info['signature']) == fuzzy_convert(pair[0])):
                new_risky_methods = []
                for risky_method in static_info['riskyMethods']:
                    if (not pair[1] or fuzzy_convert(risky_method['signature']) == fuzzy_convert(pair[1])):
                        if compact:
                            risky_method['methodWeights'] = len(risky_method['methodWeights'])
                        new_risky_methods.append(risky_method)
                if new_risky_methods:
                    static_info['riskyMethods'] = new_risky_methods
                    compact_dumps_print(static_info)


@cli.command()
@click.argument('outdir', default="./slice-only-some")
@click.option('--fscope', is_flag=True, help='Whether filter input scope')
def slice(outdir, fscope):
    global CONFIG
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    static_info = client.load_all_static_info()
    new_static_info = []
    only_some = CONFIG['only_some']
    risky_size = 0
    found_pairs = set()
    for entry in static_info:
        new_riskys = []
        for risky in entry['riskyMethods']:
            pair = (entry['signature'], risky['signature'])
            wild_entry_pair = ('*', pair[1])
            wild_risky_pair = (pair[0], '*')
            if ((pair in only_some) or (wild_entry_pair in only_some) or \
                (wild_risky_pair in only_some)):
                new_riskys.append(risky)
                if pair in found_pairs:
                    L.lprint("[!] duplicated pair {}".format(pair))
                found_pairs.add(pair)
        if new_riskys:
            risky_size += len(new_riskys)
            entry['riskyMethods'] = new_riskys
            if fscope:
                entry['scope'] = filter_scope(entry['signature'], entry['scope'])
            new_static_info.append(entry)
    L.lprint("[+] find {} static_info with {} pairs".format(len(new_static_info), risky_size))
    for pair in only_some:
        if pair not in found_pairs:
            L.lprint("[!] {} not found".format(pair))
    nid = 0
    for entry in new_static_info:
        entry_method = client.parse_signature(entry['signature'])
        name = "{}_{}_{}.json".format(entry_method['Class'].replace("$Stub$Proxy", ''), entry_method['Method'], nid)
        nid += 1
        filepath = os.path.join(outdir, name)
        with open(filepath, "w+") as f:
            json.dump([entry], f)


@cli.command()
@click.option('--entry', '-e', default="*")
@click.option('--risky', '-r', default="*")
@click.option('--vul', '-v', default="", help='Only print vulnerable')
def print_pairs(entry, risky, vul):
    if vul:
        vulns = client.load_real_vuln()[vul]
        for risky in vulns:
            for entry in vulns[risky]:
                L.lprint("[\"{}\", \"{}\"],".format(entry, risky))
        return
    static_info = client.load_all_static_info()
    count = 0
    for entry_info in static_info:
        _entry = entry_info['signature']
        if entry == '*' or entry in _entry:
            for risky_info in entry_info['riskyMethods']:
                _risky = risky_info['signature']
                if risky == '*' or risky in _risky:
                    L.lprint("[{}] {}-{}".format(count, _entry, _risky))
                    count += 1

@cli.command()
@click.option('--filt', '-f', default="")
def exception(filt):
    summary = SUMMARY
    for item in summary.values():
        exceptions = set(filter(lambda exception: filt in exception, item['exceptionMessages']))
        if exceptions:
            pair_str = item['entry'] + "-" + item['risky']
            L.lprint(pair_str)
            for exception in exceptions:
                L.lprint('\t' + exception)


@cli.command()
@click.option('--candidate', "-c", default="")
def reached(candidate):
    REACH = 0
    NOTREACH = 1
    UNCERTAIN = 2
    summary = SUMMARY
    if candidate:
        with open(candidate, 'r') as f:
            riskys = set(filter(lambda x: x, map(str.strip, f.readlines())))
    else:
        riskys = set(map(lambda entry: entry['risky'], summary.values()))
    riskys_reached = {}
    for risky in riskys:
        riskys_reached[risky] = UNCERTAIN
    for val in summary.values():
        risky = val['risky']
        if val['risky'] in riskys:
            if 'exploitationCount' not in val:
                continue
            if val['exploitationCount']:
                riskys_reached[risky] = REACH
            else:
                riskys_reached[risky] = NOTREACH

    countFor = lambda status: list(riskys_reached.values()).count(status)

    L.lprint('Reached', countFor(REACH))
    L.lprint('NotReached', countFor(NOTREACH))
    L.lprint('Uncertain', countFor(UNCERTAIN))


def compact_dumps_print(d):
    def tight(obj):
        return json.dumps(obj, separators=(',', ':'))
    L.lprint('{')
    for i, (k, v) in enumerate(d.items()):
        comma = ',' if i < len(d) else ''
        L.lprint(f'  {tight(k)}:{tight(v)}{comma}')
    L.lprint('}')


def fuzzy_convert(s):
    for m in re.findall(r'\$\w+', s):
        s = s.replace(m, '')
    return s


def print_potential(v, p, k):
    avgScore = client.get_avg_score(v)
    slope = float('nan')
    if len(v['consumptionScores']) >= 2:
        try:
            slope = client.get_consumption_slope(v)
        except:
            pass
    exploitationCount = v['exploitationCount']
    sizeChange = v['sizeChange'] if 'sizeChange' in v else 0
    var_score = client.get_var_score(v)
    crashed = v['crashed']
    L.lprint(f"[{p}] {k}; crashed:{crashed} avg:{avgScore:.2f} slope:{slope:.2f} hit:{exploitationCount} sizechg:{sizeChange} var:{var_score}")


def is_skipped(pair):
    global CONFIG, SUMMARY
    summary = SUMMARY
    skip_vuln = CONFIG['skip_vuln']
    skip_some = set(map(lambda e: (e[0], e[1]), CONFIG['skip_some']))
    only_some = set(map(lambda e: (e[0], e[1]), CONFIG['only_some']))
    DIFFERENCE = set()
    for d in CONFIG['difference_infos']:
        DIFFERENCE.update(client.load_difference(d))
    only_some.update(DIFFERENCE)
    only_interesting = CONFIG['only_interesting']
    if only_interesting:
        INTERESTING = client.load_interesting(SUMMARY, CONFIG['timeout'])
        only_some.update(INTERESTING)

    target_type = CONFIG['type']
    return client.should_skip(
        pair, target_type, summary, set(), skip_exist=False,
        skip_vuln=skip_vuln, skip_to=None, skip_some=skip_some, only_some=only_some)


def cast_to_type(paramType, value):
    register_p = r'(\$[rl][0-9]{1,2})'
    local_p = r'i[0-9]{1,2}'
    single_p = r'[ril][0-9]{1,3}'

    if value.startswith("<"):
        method = client.parse_signature(value)
        if not method:
            return value
        #Dynamic method value
        getType = lambda t: t.split('.')[-1]
        if getType(method['Ret']) != getType(paramType) and \
            getType(method['Class']) != getType(paramType):
            return ""
    else:
        if re.findall(register_p, value) or re.findall(local_p, value) or re.match(single_p, value) != None:
            return ""
        value = value.replace('\"', "")
        if value.startswith("lengthof"):
            value = ""
    return value


def get_param_type(methodSig, ind):
    params = re.findall(r'(?:\(.+\))',methodSig)
    if len(params)==0:
        return None
    params = params[0].split(',')
    return params[ind]


PRIMITIVE_TYPES = set([
    "boolean", "Boolean", "byte", "Byte", "char", "Character", "double", "Double", "float", "Float", "int", "Integer", "long", "Long", "short", "Short",
    "String", "CharSequence"
])
def filter_scope(methodSig, inputScope):
    filted_scope = {}
    for index_str in inputScope.keys():
        scope = []
        if index_str.find('.') != -1:
            paramType = None
        else:
            paramType = get_param_type(methodSig, int(index_str))
        if paramType:
            for value in inputScope[index_str]:
                if paramType not in PRIMITIVE_TYPES:
                    if isinstance(value, str):
                        continue
                result = cast_to_type(paramType, value)
                if result:
                    scope.append(result)
            filted_scope[index_str] = scope
        else:
            filted_scope[index_str] = inputScope
    return filted_scope


if __name__ == '__main__':
    cli()
