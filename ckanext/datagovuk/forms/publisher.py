import os

from flask import Blueprint

from ckan.common import c
# from ckan.controllers.organization import OrganizationController
import ckan.lib.helpers as h
import ckan.plugins as plugins
# from ckan.lib.plugins import DefaultOrganizationForm
import ckan.plugins.toolkit as toolkit
from ckan.plugins.toolkit import render, request

publisher = Blueprint('publisher', __name__)


@publisher.route('/publisher', endpoint='organizations_index')
def publishers_index():
    # org = OrganizationController()
    # return org.index()
#     return 'ok'

    page = h.get_page_number(request.params) or 1
    vars = {
        'group_type': 'organization'
    }
    c.page = h.Page([], 0)
    return render(u'organization/index.html', extra_vars=vars)

class PublisherForm(plugins.SingletonPlugin, toolkit.DefaultOrganizationForm):
    plugins.implements(plugins.IGroupForm, inherit=True)
    plugins.implements(plugins.IConfigurer, inherit=True)
    plugins.implements(plugins.IBlueprint)


    # IConfigurer

    def update_config(self, config):
        here = os.path.dirname(__file__)
        rootdir = os.path.dirname(os.path.dirname(here))

    # IGroupForm

    def form_to_db_schema(self):
        from ckan.logic.schema import group_form_schema
        schema = group_form_schema()
        for mandatory_extra in ['category']:
            schema.update({mandatory_extra: [toolkit.get_converter('convert_to_extras'),
                                         unicode]})
        for optional_extra in ['contact-name', 'contact-email', 'contact-phone', 'foi-name', 'foi-email', 'foi-web', 'foi-phone']:
            schema.update({optional_extra: [toolkit.get_validator('ignore_missing'),
                                         toolkit.get_converter('convert_to_extras'),
                                         unicode]})
        return schema

    def db_to_form_schema(self, package_type=None):
        from ckan.logic.schema import default_group_schema
        schema = default_group_schema()
        for optional_extra in ['category', 'contact-name', 'contact-email', 'contact-phone', 'foi-name', 'foi-email', 'foi-web', 'foi-phone']:
            schema.update({optional_extra: [toolkit.get_converter('convert_from_extras'),
                                         toolkit.get_validator('ignore_missing'),
                                         unicode]})
        schema['num_followers'] = []
        schema['created'] = []
        schema['display_name'] = []
        schema['package_count'] = [toolkit.get_validator('ignore_missing')]
        schema['packages'] = {'__extras': [toolkit.get_validator('keep_extras')]}
        schema['revision_id'] = []
        schema['state'] = []
        schema['users'] = {'__extras': [toolkit.get_validator('keep_extras')]}
        return schema

    def group_types(self):
       return ['organization']

    def group_controller(self):
        return 'organization'

    def is_fallback(self):
        return True

    def get_blueprint(self):
        return publisher
