from wsgiref.simple_server import make_server
from pyramid.httpexceptions import HTTPFound, HTTPForbidden
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
from settings import *
# Autenticação
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import remember, forget
from auth import groupfinder, hashed_password, check_password, get_privileges, hash_password
# Conector oficial do MongoDB
import pymongo
from pymongo import MongoClient

class appViews:
    def __init__(self, request):
        self.request = request
        self.logged_in = request.authenticated_userid
        try:
            self.privilege = get_privileges(self.logged_in)
        except:
            self.privilege = 1

    @view_config(route_name='login', renderer='login.jinja2')
    def login(self):
        request = self.request
        login_url = request.route_url('login')
        referrer = request.url
        # Verifica se o referer é a página de login, se sim muda ela pra home
        if referrer == login_url:
            referrer = '/'
        came_from = request.params.get('came_from', referrer)
        message = ''
        username = ''
        password = ''
        if 'form.submitted' in request.params:
            username = request.params['username']
            password = request.params['password']
            hashed_pw = hashed_password(username)
            if hashed_pw and check_password(password, hashed_pw):
                headers = remember(request, username)
                return HTTPFound(location=came_from,
                                 headers=headers)
            message = 'Falha no login.'

        return dict(
            name='Login',
            message=message,
            url=request.application_url + '/login',
            came_from=came_from,
            username=username,
            password=password,
        )

    @view_config(route_name='logout')
    def logout(self):
        request = self.request
        headers = forget(request)
        url = request.route_url('home')
        return HTTPFound(location=url,
                         headers=headers)
    # Views
    @view_config(
        route_name='home',
        renderer='home.jinja2'
    )
    def home(self):
        request = self.request
        # Obtém a lista de links
        db = MongoClient(
            host=DB_HOST,
            port=DB_PORT
        )
        links = db[DB_NAME]['links']
        # links = links.find()
        links = links.find().sort([("points", pymongo.DESCENDING)])

        return dict(name=self.logged_in, items=links)

    @view_config(
        route_name='user_editor',
        renderer='user_editor.jinja2'
    )
    def user_editor(self):
        request = self.request
        # Verifica se o usuário está logado
        if self.logged_in != None:
            # Verifica se ele tem privilégio para adicionar admin
            if get_privileges(self.logged_in) != 4:
                return HTTPForbidden()
            else:
                url = request.route_url('user_editor')
                referrer = request.url
                # Verifica se o referer é a página de edição, se sim muda ela pra home
                if referrer == url:
                    referrer = '/'
                came_from = request.params.get('came_from', referrer)
                message = ''
                username = ''
                password = ''
                level = ''
                if 'form.submitted' in request.params:
                    username = request.params['username']
                    password = request.params['password']
                    level = request.params['level']
                    # Inicia o DB
                    db = MongoClient(
                        host=DB_HOST,
                        port=DB_PORT
                    )
                    users = db[DB_NAME]['users']
                    if groupfinder(username, '') != None:
                        users.update_one(
                            {'username': username},
                            {'$set':{
                                'password': hash_password(password),
                                'level': int(level)
                        }})
                        return HTTPFound(location=came_from)
                    else:
                        users.insert_one({
                            'username': username,
                            'password': hash_password(password),
                            'level': int(level)
                        })
                        return HTTPFound(location=came_from)

                return dict(
                    message=message,
                    url=request.application_url + '/user_editor',
                    came_from=came_from,
                )
        else:
            return HTTPForbidden()

    @view_config(
        route_name='link_editor',
        renderer='link_editor.jinja2'
    )
    def link_editor(self):
        request = self.request
        url = request.route_url('link_editor')
        referrer = request.url
        # Verifica se o referer é a página de edição, se sim muda ela pra home
        if referrer == url:
            referrer = '/'
        came_from = request.params.get('came_from', referrer)
        # Verifica se o usuário está logado
        if self.logged_in != None:
            message = ''
            link = ''
            description = ''
            if 'form.submitted' in request.params:
                link = request.params['link']
                description = request.params['description']
                # Inicia o DB
                db = MongoClient(
                    host=DB_HOST,
                    port=DB_PORT
                )
                links = db[DB_NAME]['links']
                if links.find_one({'link': link}) == None:
                    links.insert_one({
                        'link': link,
                        'description': description,
                        'likes': 0,
                        'dislikes': 0,
                        'points': 0
                    })
                    return HTTPFound(location=came_from)
                elif get_privileges(self.logged_in) >= 2:
                    links.update_one({
                        'link': link},
                        {'$set':{
                        'description': description
                    }})
                    return HTTPFound(location=came_from)
                else:
                    message = 'Você não tem autorização para alterar esse objeto.'

            return dict(
                message=message,
                url=request.application_url + '/link',
                came_from=came_from,
            )
        else:
            return HTTPFound(location=request.route_url('login'))

    @view_config(
        route_name='link_delete',
        renderer='home'
    )
    def link_delete(self):
        request = self.request
        url = request.route_url('link_delete')
        referrer = request.url
        # Verifica se o referer é a página de edição, se sim muda ela pra home
        if referrer == url:
            referrer = '/'
        came_from = request.params.get('came_from', referrer)
        # Verifica se o usuário está logado
        if self.logged_in != None:
            link = ''
            if 'link' in request.params:
                link = request.params['link']
                # Inicia o DB
                db = MongoClient(
                    host=DB_HOST,
                    port=DB_PORT
                )
                links = db[DB_NAME]['links']
                if links.find_one({'link': link}) == None:
                    return HTTPFound(location=came_from)
                elif get_privileges(self.logged_in) >= 3:
                    links.delete_one({'link': link})
                    return HTTPFound(location=came_from)
                else:
                    return HTTPForbidden()

            return dict(
                url=request.application_url + '/link',
                came_from=came_from,
            )
        else:
            return HTTPFound(location=request.route_url('login'))

    @view_config(
        route_name='link_like',
        renderer='home'
    )
    def link_like(self):
        request = self.request
        url = request.route_url('link_like')
        referrer = request.url
        # Verifica se o referer é a página de edição, se sim muda ela pra home
        if referrer == url:
            referrer = '/'
        came_from = request.params.get('came_from', referrer)
        # Verifica se o usuário está logado
        if self.logged_in != None:
            like = 'like'
            link = ''
            if 'link' in request.params:
                link = request.params['link']
                like = request.params['like']
                # Inicia o DB
                db = MongoClient(
                    host=DB_HOST,
                    port=DB_PORT
                )
                links = db[DB_NAME]['links']
                item = links.find_one({'link': link})
                if item == None:
                    return HTTPFound(location=came_from)
                elif like == 'like':
                    links.update_one({
                        'link': link},
                        {'$set':{
                        'likes': item['likes'] + 1,
                        'points': item['likes'] - item['dislikes'] + 1
                    }})
                    return HTTPFound(location=came_from)
                else:
                    links.update_one({
                        'link': link},
                        {'$set':{
                        'dislikes': item['dislikes'] + 1,
                        'points': item['likes'] - item['dislikes'] - 1
                    }})
                    return HTTPFound(location=came_from)

            return dict(
                url=request.application_url + '/link_like',
                came_from=came_from,
            )
        else:
            return HTTPFound(location=request.route_url('login'))



if __name__ == '__main__':
    # Conecta os códigos das  views às URLS
    with Configurator() as config:
        # Autenticação
        authn_policy = AuthTktAuthenticationPolicy(
        APP_SECRET, callback=groupfinder,
        hashalg='sha512')
        authz_policy = ACLAuthorizationPolicy()
        config.set_authentication_policy(authn_policy)
        config.set_authorization_policy(authz_policy)

        # Jinja2 para usar o template do frontend
        config.include('pyramid_jinja2')

        # Views
        config.add_route('home', '/')
        config.add_route('user_editor', '/editar_usuario')
        config.add_route('link_editor', '/link')
        config.add_route('login', '/login')
        config.add_route('link_delete', '/link_delete')
        config.add_route('link_like', '/link_like')
        config.add_route('logout', '/logout')

        config.scan()
        app = config.make_wsgi_app()

    # Inicia o Servidor
    server = make_server('localhost', 8000, app)
    server.serve_forever()
