def render(template_name, context):
    from jinja2 import Template
    return Template(open(template_name).read()).render(context)
