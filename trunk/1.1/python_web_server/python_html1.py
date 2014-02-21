from string import Template

greeting = 'Artemisa 1.0.91 released!'
name = 'EB - MV - RD'
imgSrc = 'http://artemisa.sourceforge.net/wp-content/uploads/logo_for_wp.gif'
link = 'http://artemisa.sourceforge.net/'

template = Template("""\
<div>
    <h1>
        ${greeting}
    </h1>
    
    <h2>
        Project memebers: ${name}
    </h2>

    <p>
        <img src="${imgSrc}" />
    </p>

    <p>
        The project: <a href="${link}">link</a>.
    </p>
</div>""")

html = template.substitute(**locals())
#print html
print html
f = open("/home/delivery/Desktop/Workaround/Scripts/Python/web_server/python_web_server/python_html1.html", "w+")
f.write(html)
#print f
f.close()
