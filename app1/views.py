from django.shortcuts import render
from .models import files
from django.core.files.storage import FileSystemStorage
from .websake.websake import func_main

def index(request):
    template = 'index.html'
    context = {}
    if request.method == 'POST':
        try:
            a = files.objects.all()[0]
            a.delete()
        except:
            pass
        obj = files()
        a = request.FILES['apache1']
        fsa = FileSystemStorage()
        fna = fsa.save(a.name,a)
        upa = fsa.url(fna)
        obj.apache1 = upa
        b = request.FILES['envvars']
        fsb = FileSystemStorage()
        fnb = fsb.save(b.name,b)
        upb = fsb.url(fnb)
        obj.envvars = upb
        c = request.FILES['security']
        fsc = FileSystemStorage()
        fnc = fsc.save(c.name,c)
        upc = fsc.url(fnc)
        obj.security = upc
        obj.save()
        print(obj.apache1)
        f1 = open(str(obj.apache1),'r+')
        f2 = open(str(obj.envvars),'r+')
        f3 = open(str(obj.security),'r+')
        print(f1,'\n',f2,'\n',f3)
        txt = func_main(f3,f2,f1)
        context['output'] = txt
    return render(request,template,context)