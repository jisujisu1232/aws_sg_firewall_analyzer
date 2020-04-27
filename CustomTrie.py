class TrieNode:
    def __init__(self,char):
        self.char=char
        self.childNodes=[]
        self.terminal=False
        self.values=[]
    def subNode(self,char):
        if self.childNodes:
            for cN in self.childNodes:
                if cN.char==char:
                    return cN
        return None

class Trie:
    def __init__(self, input_list, ctype='default'):
        self.root=TrieNode(0)
        self.type=ctype
        self.input_list=input_list
        self.insertAll()

    def search(self, str):
        current = self.root
        for s in str:
            if current.terminal:
                return True
            next = current.subNode(s)
            if next == None:
                return False
            current = next
        return current.terminal

    def searchAll(self, str):
        return_arr = []
        current = self.root
        for s in str:
            if current.terminal:
                return_arr+=current.values
            next = current.subNode(s)
            if next == None:
                break
            current = next
        return return_arr

    def insert(self, key, value):
        # if self.search(key):
        #     return current
        current = self.root
        for s in key:
            next = current.subNode(s)
            if not next:
                current.childNodes.append(TrieNode(s))
                next = current.subNode(s)
            current=next
        current.terminal=True
        if value:
            current.values.append(value)
        return current

    def insertAll(self):
        for d in self.input_list:
            if self.type=='kv':
                self.insert(d['Key'], d['Value'])
            else:
                self.insert(d, None)
