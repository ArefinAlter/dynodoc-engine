# Writes the inputs of wasm-parity-v1.json from v1-log.json; outputs are then filled once by
# `DYNODOC_FILL_PARITY=1 cargo test -p dynodoc-engine-wasm --test parity` and frozen.
# Usage: python -X utf8 gen_wasm_parity_inputs.py v1-log.json wasm-parity-v1.json
import json, sys
src = sys.argv[1]; out = sys.argv[2]
log = json.load(open(src, encoding='utf8'))
def arr(h): return list(bytes.fromhex(h))
events = []
for e in log['events']:
    events.append({
        'id': e['id'], 'document_id': log['document_id'], 'seq': e['seq'], 'type': e['type'],
        'actor_id': log['actor_id'], 'target_node_id': e['target_node_id'], 'payload': e['payload'],
        'content_hash': arr(e['content_hash']), 'prev_chain_hash': arr(e['prev_chain_hash']),
        'chain_hash': arr(e['chain_hash']), 'created_at': '2026-11-06T00:00:00Z'})
js_form = [
  r'{"b":1,"a":[true,false,null],"c":{"z":"x","y":"\u0000\u001f\"\\/\b\f\n\r\t"}}',
  r'{"\ud83d\ude00":1,"\uff5e":2,"a":3,"B":4,"":5,"\u00e9":6}',
  r'[123456789012345680000,0,1,-1,1.5,-1.5,0.1,0.30000000000000004,1e-7,0.000001,0.00001,0.000025,1e+21,10000000000000000,18446744073709552000,9007199254740992,-9223372036854776000,5e-324,1.7976931348623157e+308,-2.5e-8,123.456,100,1e+300,4.35,0.1234567890123]',
  r'{"cell_1":"Total","cell_2":1234.5,"cell_3":0.000001,"cell_4":1e+21,"block_hash":"ignored"}',
  r'["\u2028\u2029","\u007f","caf\u00e9","\ud83d\ude00",""]',
  '{"type":"paragraph","attrs":{"blockId":"01JA0000000000000000000003","textAlign":null},"content":[{"type":"text","text":"Synthetic text","marks":[{"type":"bold"}]}]}',
]
lexemes = ['1.0', '100.0', '1E2', '-0', '18446744073709551615', '18446744073709551616', '-9223372036854775808', '-9223372036854775809', ' { "a" : [ 1 , 2 ] } ']
def p(text):
    return {'type':'paragraph','attrs':{'blockId':'stable'},'content':[{'type':'text','text':text}]}
def state(nodes):
    st = {'nodes': {}, 'comments': [], 'suggestions': {}, 'removed_choices': []}
    st['nodes']['root'] = {'id':'root','parent_id':None,'type':'form','pos':'a0','current_fields':{'title':'Synthetic'},'var_name':None,'deleted':False}
    for i,(nid, content) in enumerate(nodes):
        st['nodes'][nid] = {'id':nid,'parent_id':'root','type':'item','pos':'a%d' % (i+1),'current_fields':{'label':''.join(c['text'] for c in content['content']), 'content':content},'var_name':None,'deleted':False}
    return st
long_base = 'x' * 2100
merges = [
  {'name':'disjoint edits in one paragraph merge','base':state([('stable',p('The participants were interviewed in June.'))]),'team':state([('stable',p('The respondents were interviewed in June.'))]),'draft':state([('stable',p('The participants were interviewed in July.'))]),'resolutions':{}},
  {'name':'overlapping edits conflict','base':state([('stable',p('abcdefghij'))]),'team':state([('stable',p('abUVWXYZij'))]),'draft':state([('stable',p('ABcdeZghij'))]),'resolutions':{}},
  {'name':'overlapping edits resolved with the draft','base':state([('stable',p('abcdefghij'))]),'team':state([('stable',p('abUVWXYZij'))]),'draft':state([('stable',p('ABcdeZghij'))]),'resolutions':{'stable:content':'draft'}},
  {'name':'edits to different blocks merge','base':state([('one',p('First.')),('two',p('Second.'))]),'team':state([('one',p('First, edited by the team.')),('two',p('Second.'))]),'draft':state([('one',p('First.')),('two',p('Second, edited in the draft.'))]),'resolutions':{}},
  {'name':'a change over the size budget is one replacement and conflicts','base':state([('stable',p('a' + long_base + 'z'))]),'team':state([('stable',p('A' + 'y'*2100 + 'z'))]),'draft':state([('stable',p('a' + 'w'*2100 + 'Z'))]),'resolutions':{}},
  {'name':'the same change on both sides is not a conflict','base':state([('stable',p('Draft one.'))]),'team':state([('stable',p('Draft two.'))]),'draft':state([('stable',p('Draft two.'))]),'resolutions':{}},
]
text_merges = [
  {'name':'non-overlapping hunks','base':p('The participants were interviewed in June.'),'team':p('The respondents were interviewed in June.'),'draft':p('The participants were interviewed in July.')},
  {'name':'adjacent hunk hides a later overlap','base':p('abcdefghij'),'team':p('abUVWXYZij'),'draft':p('ABcdeZghij')},
  {'name':'competing insertions at one point','base':p('ab'),'team':p('axb'),'draft':p('ayb')},
  {'name':'Bengali text','base':p('আমি বাংলায় গান গাই।'),'team':p('আমরা বাংলায় গান গাই।'),'draft':p('আমি বাংলায় কবিতা গাই।')},
]
doc = {
  'description': 'Parity vectors v1 (decision 036): the native engine and its WebAssembly build must reproduce every output bit for bit, and the SDK reproduces the js_form canonical cases without WebAssembly. Outputs were computed once by the native engine and frozen; never regenerate them to make a failing test pass: a mismatch means canonical JSON, a hash, the fold or the merge changed on some target. Events are the v1 golden log (v1-log.json) in the form GET /documents/{id}/events returns. All data is synthetic.',
  'canonical_js_form': [{'input': t} for t in js_form],
  'canonical_lexemes': [{'input': t} for t in lexemes],
  'chain': {'events': events, 'after_seq': 0, 'after_chain_hash': '0'*64},
  'merges': merges,
  'text_merges': text_merges,
}
json.dump(doc, open(out, 'w', encoding='utf8', newline='\n'), ensure_ascii=False, indent=1)
open(out,'a',encoding='utf8',newline='\n').write('\n')
