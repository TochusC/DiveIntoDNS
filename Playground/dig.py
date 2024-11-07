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

# dig @127.0.0.1 re1.re2.re3.re4.re5.re6.re7.re8.re9.re10.re11.re12.re13.re14.re15.re16.re17.re18.re19.re20.re21.re22.re23.re24.re25.re26.re27.re28.re29.re30.re31.re32.re33.re34.re35.re36.re37.re38.re39.re40.re41.re42.re43.re44.re45.re46.re47.re48.re49.re50.re51.re52.test