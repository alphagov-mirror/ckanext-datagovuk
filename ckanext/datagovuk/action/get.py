import json
import socket

from ckan import authz, logic, plugins
from ckan.lib import search
import ckan.lib.plugins as lib_plugins
import ckan.logic.schema
from ckan.logic.action.get import package_search
from ckan.logic import get_action as logic_get_action
from ckan.plugins.toolkit import (
    abort,
    check_access,
    navl_validate,
    side_effect_free,
    ValidationError,
    get_action,
)
import ckan.lib.dictization.model_save as model_save
import ckan.lib.dictization.model_dictize as model_dictize

from ckan.model import User
from paste.deploy.converters import asbool

log = __import__('logging').getLogger(__name__)


# defined as they are in ckan/action/get.py to save further hacks to the
# function copied from there
_check_access = check_access
_get_or_bust = logic.get_or_bust
_validate = navl_validate
NotFound = logic.NotFound

PII_LIST = [
    'author',
    'author_email',
    'contact-name',
    'contact-phone',
    'contact-email',
    'maintainer',
    'maintainer_email'
]


def user_auth(context, data_dict):
    '''Authenticates a user

    You must be a system administrator to authenticate users.

    :param email: the email address of the user
    :type email: string
    :param password: the password of the user
    :type password: string

    :returns: the newly created user
    :rtype: dictionary

    '''
    model = context['model']
    session = context['session']

    _check_access('user_auth', context, data_dict)

    email = data_dict.get('email')
    password = data_dict.get('password')

    if not (email and password):
        raise ValidationError(['email and password are both required'])

    users = User.by_email(email)
    user = users[0] if users else None

    if (user is None) or \
            (not user.is_active()) or \
            (not user.validate_password(password)):
        raise ValidationError(['There was a problem authenticating this user'])

    user_dict = model_dictize.user_dictize(user, context)

    ## Get the user's organisation list to return with the login details
    fOrgList = get_action('organization_list_for_user')
    user_dict['organisations'] = fOrgList(context, {'id': user.name})

    # DGU Hack: added encoding so we don't barf on unicode user names
    log.debug('Authenticated user {name}'.format(name=user.name.encode('utf8')))
    return user_dict


@side_effect_free
def package_search(context, data_dict):
    # Extracted from ckan core: 
    # https://github.com/ckan/ckan/blob/20a506ddbce33c92e3dfc510e1f1d7097caa45f9/ckan/logic/action/get.py#L1716-L1997
    '''
    Searches for packages satisfying a given search criteria.

    This action accepts solr search query parameters (details below), and
    returns a dictionary of results, including dictized datasets that match
    the search criteria, a search count and also facet information.

    **Solr Parameters:**

    For more in depth treatment of each paramter, please read the `Solr
    Documentation <http://wiki.apache.org/solr/CommonQueryParameters>`_.

    This action accepts a *subset* of solr's search query parameters:


    :param q: the solr query.  Optional.  Default: ``"*:*"``
    :type q: string
    :param fq: any filter queries to apply.  Note: ``+site_id:{ckan_site_id}``
        is added to this string prior to the query being executed.
    :type fq: string
    :param sort: sorting of the search results.  Optional.  Default:
        ``'relevance asc, metadata_modified desc'``.  As per the solr
        documentation, this is a comma-separated string of field names and
        sort-orderings.
    :type sort: string
    :param rows: the number of matching rows to return. There is a hard limit
        of 1000 datasets per query.
    :type rows: int
    :param start: the offset in the complete result for where the set of
        returned datasets should begin.
    :type start: int
    :param facet: whether to enable faceted results.  Default: ``True``.
    :type facet: string
    :param facet.mincount: the minimum counts for facet fields should be
        included in the results.
    :type facet.mincount: int
    :param facet.limit: the maximum number of values the facet fields return.
        A negative value means unlimited. This can be set instance-wide with
        the :ref:`search.facets.limit` config option. Default is 50.
    :type facet.limit: int
    :param facet.field: the fields to facet upon.  Default empty.  If empty,
        then the returned facet information is empty.
    :type facet.field: list of strings
    :param include_drafts: if ``True``, draft datasets will be included in the
        results. A user will only be returned their own draft datasets, and a
        sysadmin will be returned all draft datasets. Optional, the default is
        ``False``.
    :type include_drafts: boolean
    :param include_private: if ``True``, private datasets will be included in
        the results. Only private datasets from the user's organizations will
        be returned and sysadmins will be returned all private datasets.
        Optional, the default is ``False``.
    :param use_default_schema: use default package schema instead of
        a custom schema defined with an IDatasetForm plugin (default: False)
    :type use_default_schema: bool


    The following advanced Solr parameters are supported as well. Note that
    some of these are only available on particular Solr versions. See Solr's
    `dismax`_ and `edismax`_ documentation for further details on them:

    ``qf``, ``wt``, ``bf``, ``boost``, ``tie``, ``defType``, ``mm``


    .. _dismax: http://wiki.apache.org/solr/DisMaxQParserPlugin
    .. _edismax: http://wiki.apache.org/solr/ExtendedDisMax


    **Examples:**

    ``q=flood`` datasets containing the word `flood`, `floods` or `flooding`
    ``fq=tags:economy`` datasets with the tag `economy`
    ``facet.field=["tags"] facet.limit=10 rows=0`` top 10 tags

    **Results:**

    The result of this action is a dict with the following keys:

    :rtype: A dictionary with the following keys
    :param count: the number of results found.  Note, this is the total number
        of results found, not the total number of results returned (which is
        affected by limit and row parameters used in the input).
    :type count: int
    :param results: ordered list of datasets matching the query, where the
        ordering defined by the sort parameter used in the query.
    :type results: list of dictized datasets.
    :param facets: DEPRECATED.  Aggregated information about facet counts.
    :type facets: DEPRECATED dict
    :param search_facets: aggregated information about facet counts.  The outer
        dict is keyed by the facet field name (as used in the search query).
        Each entry of the outer dict is itself a dict, with a "title" key, and
        an "items" key.  The "items" key's value is a list of dicts, each with
        "count", "display_name" and "name" entries.  The display_name is a
        form of the name that can be used in titles.
    :type search_facets: nested dict of dicts.

    An example result: ::

     {'count': 2,
      'results': [ { <snip> }, { <snip> }],
      'search_facets': {u'tags': {'items': [{'count': 1,
                                             'display_name': u'tolstoy',
                                             'name': u'tolstoy'},
                                            {'count': 2,
                                             'display_name': u'russian',
                                             'name': u'russian'}
                                           ]
                                 }
                       }
     }

    **Limitations:**

    The full solr query language is not exposed, including.

    fl
        The parameter that controls which fields are returned in the solr
        query.
        fl can be  None or a list of result fields, such as ['id', 'extras_custom_field'].
        if fl = None, datasets are returned as a list of full dictionary.
    '''
    # sometimes context['schema'] is None
    schema = (context.get('schema') or
              logic.schema.default_package_search_schema())
    data_dict, errors = _validate(data_dict, schema, context)
    # put the extras back into the data_dict so that the search can
    # report needless parameters
    data_dict.update(data_dict.get('__extras', {}))
    data_dict.pop('__extras', None)
    if errors:
        raise ValidationError(errors)

    model = context['model']
    session = context['session']
    user = context.get('user')

    _check_access('package_search', context, data_dict)

    # Move ext_ params to extras and remove them from the root of the search
    # params, so they don't cause and error
    data_dict['extras'] = data_dict.get('extras', {})
    for key in [key for key in data_dict.keys() if key.startswith('ext_')]:
        data_dict['extras'][key] = data_dict.pop(key)

    # check if some extension needs to modify the search params
    for item in plugins.PluginImplementations(plugins.IPackageController):
        data_dict = item.before_search(data_dict)

    # the extension may have decided that it is not necessary to perform
    # the query
    abort = data_dict.get('abort_search', False)

    if data_dict.get('sort') in (None, 'rank'):
        data_dict['sort'] = 'score desc, metadata_modified desc'

    results = []
    if not abort:
        if asbool(data_dict.get('use_default_schema')):
            data_source = 'data_dict'
        else:
            data_source = 'validated_data_dict'
        data_dict.pop('use_default_schema', None)

        result_fl = data_dict.get('fl')
        if not result_fl:
            data_dict['fl'] = 'id {0}'.format(data_source)
        else:
            data_dict['fl'] = ' '.join(result_fl)

        # Remove before these hit solr FIXME: whitelist instead
        include_private = asbool(data_dict.pop('include_private', False))
        include_drafts = asbool(data_dict.pop('include_drafts', False))
        data_dict.setdefault('fq', '')
        if not include_private:
            data_dict['fq'] = '+capacity:public ' + data_dict['fq']
        if include_drafts:
            data_dict['fq'] += ' +state:(active OR draft)'

        # Pop these ones as Solr does not need them
        extras = data_dict.pop('extras', None)

        # enforce permission filter based on user
        if context.get('ignore_auth') or (user and authz.is_sysadmin(user)):
            labels = None
        else:
            labels = lib_plugins.get_permission_labels(
                ).get_user_dataset_labels(context['auth_user_obj'])

        query = search.query_for(model.Package)
        query.run(data_dict, permission_labels=labels)

        # Add them back so extensions can use them on after_search
        data_dict['extras'] = extras

        if result_fl:
            for package in query.results:
                if package.get('extras'):
                    package.update(package['extras'] )
                    package.pop('extras')
                results.append(package)
        else:
            for package in query.results:
                # get the package object
                package_dict = package.get(data_source)
                ## use data in search index if there
                if package_dict:
                    # the package_dict still needs translating when being viewed
                    package_dict = json.loads(package_dict)
                    if context.get('for_view'):
                        for item in plugins.PluginImplementations(
                                plugins.IPackageController):
                            package_dict = item.before_view(package_dict)
                    results.append(package_dict)
                else:
                    log.error('No package_dict is coming from solr for package '
                              'id %s', package['id'])

        count = query.count
        facets = query.facets
    else:
        count = 0
        facets = {}
        results = []

    search_results = {
        'count': count,
        'facets': facets,
        'results': results,
        'sort': data_dict['sort']
    }

    # create a lookup table of group name to title for all the groups and
    # organizations in the current search's facets.
    group_names = []
    for field_name in ('groups', 'organization'):
        group_names.extend(facets.get(field_name, {}).keys())

    groups = (session.query(model.Group.name, model.Group.title)
                    .filter(model.Group.name.in_(group_names))
                    .all()
              if group_names else [])
    group_titles_by_name = dict(groups)

    # Transform facets into a more useful data structure.
    restructured_facets = {}
    for key, value in facets.items():
        if key in ('contact-name', 'contact-phone', 'contact-email'):
            print('contact', key)
            continue

        restructured_facets[key] = {
            'title': key,
            'items': []
        }
        for key_, value_ in value.items():
            new_facet_dict = {}
            new_facet_dict['name'] = key_
            if key in ('groups', 'organization'):
                display_name = group_titles_by_name.get(key_, key_)
                display_name = display_name if display_name and display_name.strip() else key_
                new_facet_dict['display_name'] = display_name
            elif key == 'license_id':
                license = model.Package.get_license_register().get(key_)
                if license:
                    new_facet_dict['display_name'] = license.title
                else:
                    new_facet_dict['display_name'] = key_
            else:
                new_facet_dict['display_name'] = key_
            new_facet_dict['count'] = value_
            restructured_facets[key]['items'].append(new_facet_dict)
    search_results['search_facets'] = restructured_facets

    # check if some extension needs to modify the search results
    for item in plugins.PluginImplementations(plugins.IPackageController):
        search_results = item.after_search(search_results, data_dict)

    # After extensions have had a chance to modify the facets, sort them by
    # display name.
    for facet in search_results['search_facets']:
        search_results['search_facets'][facet]['items'] = sorted(
            search_results['search_facets'][facet]['items'],
            key=lambda facet: facet['display_name'], reverse=True)

    return remove_pii_from_list(search_results)


@side_effect_free
def package_show(context, data_dict):
    # Extracted from ckan core:
    # https://github.com/ckan/ckan/blob/20a506ddbce33c92e3dfc510e1f1d7097caa45f9/ckan/logic/action/get.py#L958-L1052
    '''Return the metadata of a dataset (package) and its resources.

    :param id: the id or name of the dataset
    :type id: string
    :param use_default_schema: use default package schema instead of
        a custom schema defined with an IDatasetForm plugin (default: False)
    :type use_default_schema: bool
    :param include_tracking: add tracking information to dataset and
        resources (default: False)
    :type include_tracking: bool
    :rtype: dictionary

    '''
    model = context['model']
    context['session'] = model.Session
    name_or_id = data_dict.get("id") or _get_or_bust(data_dict, 'name_or_id')

    pkg = model.Package.get(name_or_id)

    if pkg is None:
        raise NotFound

    context['package'] = pkg

    _check_access('package_show', context, data_dict)

    if data_dict.get('use_default_schema', False):
        context['schema'] = ckan.logic.schema.default_show_package_schema()
    include_tracking = asbool(data_dict.get('include_tracking', False))

    package_dict = None
    use_cache = (context.get('use_cache', True)
                 and not 'revision_id' in context
                 and not 'revision_date' in context)

    if use_cache:
        try:
            search_result = search.show(name_or_id)
        except (search.SearchError, socket.error):
            pass
        else:
            use_validated_cache = 'schema' not in context
            if use_validated_cache and 'validated_data_dict' in search_result:
                package_json = search_result['validated_data_dict']
                package_dict = json.loads(package_json)
                package_dict_validated = True
            else:
                package_dict = json.loads(search_result['data_dict'])
                package_dict_validated = False
            metadata_modified = pkg.metadata_modified.isoformat()
            search_metadata_modified = search_result['metadata_modified']
            # solr stores less precice datetime,
            # truncate to 22 charactors to get good enough match
            if metadata_modified[:22] != search_metadata_modified[:22]:
                package_dict = None

    if not package_dict:
        package_dict = model_dictize.package_dictize(pkg, context)
        package_dict_validated = False

    if include_tracking:
        # page-view tracking summary data
        package_dict['tracking_summary'] = (
            model.TrackingSummary.get_for_package(package_dict['id']))

        for resource_dict in package_dict['resources']:
            _add_tracking_summary_to_resource_dict(resource_dict, model)

    if context.get('for_view'):
        for item in plugins.PluginImplementations(plugins.IPackageController):
            package_dict = item.before_view(package_dict)

    for item in plugins.PluginImplementations(plugins.IPackageController):
        item.read(pkg)

    for item in plugins.PluginImplementations(plugins.IResourceController):
        for resource_dict in package_dict['resources']:
            item.before_show(resource_dict)

    if not package_dict_validated:
        package_plugin = lib_plugins.lookup_package_plugin(
            package_dict['type'])
        if 'schema' in context:
            schema = context['schema']
        else:
            schema = package_plugin.show_package_schema()
        if schema and context.get('validate', True):
            package_dict, errors = lib_plugins.plugin_validate(
                package_plugin, context, package_dict, schema,
                'package_show')

    for item in plugins.PluginImplementations(plugins.IPackageController):
        item.after_show(context, package_dict)

    return remove_pii(package_dict)


def remove_pii_from_list(search_results):
    for element in search_results['results']:
        remove_pii(element)
    return search_results


def remove_pii(element):
    for key in element.keys():
        if key in PII_LIST:
            del element[key]
    return element
