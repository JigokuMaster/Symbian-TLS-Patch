import os

def export_headers(p, out):
    for f in os.listdir(p):
        fp = os.path.join(p, f)
        if os.path.isfile(fp):
            expoort_target = '../include/%s/%s' %(p, f)
            expoort_dest =  '%s/%s' %(p, f)
            print(expoort_target, expoort_dest)
            out.write('%s\t%s\n' %(expoort_target, expoort_dest))

with open('expoorts.txt', 'w') as out:
    for f in os.listdir('.'):
        if os.path.isdir(f):
            export_headers(f, out)
            
        