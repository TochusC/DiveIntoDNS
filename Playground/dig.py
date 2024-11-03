from tkinter import N


depth = 53
arr = [str(i) for i in range(depth)]    
sep = ".re"
rst = sep.join(arr)
name = rst[2:] + ".test"
labels = len(name.split("."))
print(f"Length: {len(name)}, Lables Num: {labels}\n")    
cmd = "dig @127.0.0.1 " + rst[2:] + ".test"
print(cmd)