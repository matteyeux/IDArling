# Careful: there is a callback called when the IDB is closed or when we connect
# to the server so the netnode is recreated if idarling is running which we want
# to avoid.
# A workaround is to temporarily disable idarling by removing the plugin so it
# does not load to avoid the netnode to be recreated but it is annoying.
# A better way is to set IDAUSR to a path that does not exists so no plugin is loaded
# see ida_noplugin.bat
import ida_netnode

NETNODE_NAME = "$ idarling"
node = ida_netnode.netnode(NETNODE_NAME)
if ida_netnode.exist(node):
    node.kill()
    print('[+] "%s" node killed in action' % NETNODE_NAME)
else:
    print('[x] "%s" node does not exist' % NETNODE_NAME)
