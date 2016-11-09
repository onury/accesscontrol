/* eslint brace-style:0, max-statements-per-line:0 */

/**
 *  Test Suite: AccessControl (Core)
 *  @author   Onur Yıldırım (onur@cutepilot.com)
 */

var AccessControl = require('../index');

describe('Test Suite: Access Control (core)', function () {
    'use strict';

    // grant list fetched from DB (to be converted to a valid grants object)
    var grantList = [
        { role: 'admin', resource: 'video', action: 'create:any', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'read:any', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'update:any', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'delete:any', attributes: ['*'] },

        { role: 'user', resource: 'video', action: 'create:own', attributes: ['*'] },
        { role: 'user', resource: 'video', action: 'read:any', attributes: ['*'] },
        { role: 'user', resource: 'video', action: 'update:own', attributes: ['*'] },
        { role: 'user', resource: 'video', action: 'delete:own', attributes: ['*'] }
    ];

    // valid grants object
    var grantsObject = {
        admin: {
            video: {
                'create:any': ['*'],
                'read:any': ['*'],
                'update:any': ['*'],
                'delete:any': ['*']
            }
        },
        user: {
            video: {
                'create:own': ['*'],
                'read:own': ['*'],
                'update:own': ['*'],
                'delete:own': ['*']
            }
        }
    };

    beforeEach(function () {
        this.ac = new AccessControl();
    });

    //----------------------------
    //  TESTS
    //----------------------------

    it('should add grants from flat list (db), check/remove roles and resources', function () {
        var ac = this.ac;
        ac.setGrants(grantList);
        // console.log('grants', ac.getGrants());
        // console.log('resources', ac.getResources());
        // console.log('roles', ac.getRoles());

        expect(ac.getRoles().length).toEqual(2);
        expect(ac.getResources().length).toEqual(1);
        expect(ac.hasRole('admin')).toEqual(true);
        expect(ac.hasRole('user')).toEqual(true);
        expect(ac.hasRole('moderator')).toEqual(false);
        expect(ac.hasResource('video')).toEqual(true);
        expect(ac.hasResource('photo')).toEqual(false);
        // removeRoles should also accept a string
        ac.removeRoles('admin');
        expect(ac.hasRole('admin')).toEqual(false);
        // no role named moderator but this should work
        ac.removeRoles(['user', 'moderator']);
        expect(ac.getRoles().length).toEqual(0);
        // removeRoles should accept a string or array
        ac.removeResources(['video']);
        expect(ac.getResources().length).toEqual(0);
        expect(ac.hasResource('video')).toEqual(false);
    });

    it('should grant/deny access and check permissions', function () {
        var ac = this.ac,
            attrs = ['*', '!size'];

        ac.grant('user').createAny('photo', attrs);
        expect(ac.getGrants().user.photo['create:any']).toEqual(attrs);
        expect(ac.can('user').createAny('photo').attributes).toEqual(attrs);

        ac.deny('user').createAny('photo');
        expect(ac.can('user').createAny('photo').granted).toEqual(false);
        expect(ac.can('user').createAny('photo').attributes).toEqual([]);

        ac.grant('user').createOwn('photo', attrs);
        // console.log('ac.getGrants()', ac.getGrants());
        expect(ac.getGrants().user.photo['create:own']).toEqual(attrs);
        expect(ac.can('user').createOwn('photo').attributes).toEqual(attrs);

        // grant multiple roles the same permission for the same resource
        ac.grant(['user', 'admin']).readAny('photo', attrs);
        expect(ac.can('user').readAny('photo').granted).toEqual(true);
        expect(ac.can('admin').readAny('photo').granted).toEqual(true);
        // deny multiple roles the same permission for the same resource
        ac.deny(['user', 'admin']).readAny('photo');
        expect(ac.can('user').readAny('photo').granted).toEqual(false);
        expect(ac.can('admin').readAny('photo').granted).toEqual(false);

        ac.grant('user').updateAny('photo', attrs);
        expect(ac.getGrants().user.photo['update:any']).toEqual(attrs);
        expect(ac.can('user').updateAny('photo').attributes).toEqual(attrs);

        ac.grant('user').updateOwn('photo', attrs);
        expect(ac.getGrants().user.photo['update:own']).toEqual(attrs);
        expect(ac.can('user').updateOwn('photo').attributes).toEqual(attrs);

        ac.grant('user').deleteAny('photo', attrs);
        expect(ac.getGrants().user.photo['delete:any']).toEqual(attrs);
        expect(ac.can('user').deleteAny('photo').attributes).toEqual(attrs);

        ac.grant('user').deleteOwn('photo', attrs);
        expect(ac.getGrants().user.photo['delete:own']).toEqual(attrs);
        expect(ac.can('user').deleteOwn('photo').attributes).toEqual(attrs);
    });

    it('should chain grant methods and check permissions', function () {
        var ac = this.ac,
            attrs = ['*'];

        ac.grant('superadmin')
            .createAny('profile', attrs)
            .readAny('profile', attrs)
            .createAny('video', []) // no attributes allowed
            .createAny('photo'); // all attributes allowed

        expect(ac.can('superadmin').createAny('profile').granted).toEqual(true);
        expect(ac.can('superadmin').readAny('profile').granted).toEqual(true);
        expect(ac.can('superadmin').createAny('video').granted).toEqual(false);
        expect(ac.can('superadmin').createAny('photo').granted).toEqual(true);
    });

    it('should grant/deny access via object and check permissions', function () {
        var ac = this.ac,
            attrs = ['*'];

        var o1 = {
            role: 'moderator',
            resource: 'post',
            action: 'create:any', // action:possession
            attributes: ['*'] // grant only
        };
        var o2 = {
            role: 'moderator',
            resource: 'news',
            action: 'read', // separate action
            possession: 'own', // separate possession
            attributes: ['*'] // grant only
        };
        var o3 = {
            role: 'moderator',
            resource: 'book',
            // no action/possession set
            attributes: ['*'] // grant only
        };

        ac.grant(o1);
        ac.grant(o2);
        ac.grant(o3).updateAny();

        expect(ac.can('moderator').createAny('post').granted).toEqual(true);
        expect(ac.can('moderator').readOwn('news').granted).toEqual(true);
        expect(ac.can('moderator').updateAny('book').granted).toEqual(true);

        ac.deny(o1);
        ac.deny(o2);
        ac.deny(o3).updateAny();

        expect(ac.can('moderator').createAny('post').granted).toEqual(false);
        expect(ac.can('moderator').readOwn('news').granted).toEqual(false);
        expect(ac.can('moderator').updateAny('book').granted).toEqual(false);

        // should overwrite already defined action/possession in o1 object
        ac.grant(o1).readOwn();
        expect(ac.can('moderator').readOwn('post').granted).toEqual(true);
        ac.deny(o1).readOwn();
        expect(ac.can('moderator').readOwn('post').granted).toEqual(false);

        // non-set action (update:own)
        expect(ac.can('moderator').updateOwn('news').granted).toEqual(false);
        // non-existent resource
        expect(ac.can('moderator').createAny('foo').granted).toEqual(false);
    });

    it('should grant/deny access (variation, chained)', function () {
        var ac = this.ac;
        ac.setGrants(grantsObject);

        expect(ac.can('admin').createAny('video').granted).toEqual(true);
        ac.deny('admin').create('video');
        expect(ac.can('admin').createAny('video').granted).toEqual(false);

        ac.grant('foo').createOwn('bar');
        expect(ac.can('foo').createAny('bar').granted).toEqual(false);
        expect(ac.can('foo').createOwn('bar').granted).toEqual(true);

        ac.grant('foo').create('baz', []); // no attributes, actually denied instead of granted
        expect(ac.can('foo').create('baz').granted).toEqual(false);

        ac.grant('qux')
            .createOwn('resource1')
            .updateOwn('resource2')
            .readAny('resource1')
            .deleteAny('resource1', []);
        expect(ac.can('qux').createOwn('resource1').granted).toEqual(true);
        expect(ac.can('qux').updateOwn('resource2').granted).toEqual(true);
        expect(ac.can('qux').readAny('resource1').granted).toEqual(true);
        expect(ac.can('qux').deleteAny('resource1').granted).toEqual(false);

        ac.deny('qux')
            .createOwn('resource1')
            .updateOwn('resource2')
            .readAny('resource1')
            .deleteAny('resource1', []);
        expect(ac.can('qux').createOwn('resource1').granted).toEqual(false);
        expect(ac.can('qux').updateOwn('resource2').granted).toEqual(false);
        expect(ac.can('qux').readAny('resource1').granted).toEqual(false);
        expect(ac.can('qux').deleteAny('resource1').granted).toEqual(false);

        ac.grant('editor').resource('file1').updateAny();
        ac.grant().role('editor').updateAny('file2');
        ac.grant().role('editor').resource('file3').updateAny();
        expect(ac.can('editor').updateAny('file1').granted).toEqual(true);
        expect(ac.can('editor').updateAny('file2').granted).toEqual(true);
        expect(ac.can('editor').updateAny('file3').granted).toEqual(true);

        ac.deny('editor').resource('file1').updateAny();
        ac.deny().role('editor').updateAny('file2');
        ac.deny().role('editor').resource('file3').updateAny();
        expect(ac.can('editor').updateAny('file1').granted).toEqual(false);
        expect(ac.can('editor').updateAny('file2').granted).toEqual(false);
        expect(ac.can('editor').updateAny('file3').granted).toEqual(false);

        ac.grant('editor')
            .resource('fileX').readAny().createOwn()
            .resource('fileY').updateOwn().deleteOwn();
        expect(ac.can('editor').readAny('fileX').granted).toEqual(true);
        expect(ac.can('editor').createOwn('fileX').granted).toEqual(true);
        expect(ac.can('editor').updateOwn('fileY').granted).toEqual(true);
        expect(ac.can('editor').deleteOwn('fileY').granted).toEqual(true);

        ac.deny('editor')
            .resource('fileX').readAny().createOwn()
            .resource('fileY').updateOwn().deleteOwn();
        expect(ac.can('editor').readAny('fileX').granted).toEqual(false);
        expect(ac.can('editor').createOwn('fileX').granted).toEqual(false);
        expect(ac.can('editor').updateOwn('fileY').granted).toEqual(false);
        expect(ac.can('editor').deleteOwn('fileY').granted).toEqual(false);

    });

    it('should switch-chain grant/deny roles', function () {
        var ac = this.ac;
        ac.grant('r1')
                .createOwn('a')
            .grant('r2')
                .createOwn('b')
                .readAny('b')
            .deny('r1')
                .deleteAny('b')
            .grant('r1')
                .updateAny('c')
            .deny('r2')
                .readAny('c');

        expect(ac.can('r1').createOwn('a').granted).toEqual(true);
        expect(ac.can('r1').deleteAny('b').granted).toEqual(false);
        expect(ac.can('r1').updateAny('c').granted).toEqual(true);
        expect(ac.can('r2').createOwn('b').granted).toEqual(true);
        expect(ac.can('r2').readAny('b').granted).toEqual(true);
        expect(ac.can('r2').readAny('c').granted).toEqual(false);
        // console.log(JSON.stringify(ac.getGrants(), null, '  '));
    });

    it('should extend / remove roles', function () {
        var ac = this.ac;

        ac.extendRole('onur', 'admin');
        expect(ac.getGrants().onur.$extend.length).toEqual(1);
        expect(ac.getGrants().onur.$extend[0]).toEqual('admin');

        ac.extendRole('onur', ['role2', 'role3']);
        expect(ac.getGrants().onur.$extend).toEqual(['admin', 'role2', 'role3']);

        ac.grant('admin').extend('editor');
        expect(ac.getGrants().admin.$extend).toEqual(['editor']);
        ac.grant('admin').extend(['viewer', 'editor', 'agent']).readAny('video');
        expect(ac.getGrants().admin.$extend).toContain('editor');
        expect(ac.getGrants().admin.$extend).toEqual(['editor', 'viewer', 'agent']);

        ac.grant(['editor', 'agent']).extend(['role2', 'role3']).updateOwn('photo');
        expect(ac.getGrants().editor.$extend).toEqual(['role2', 'role3']);
        expect(ac.getGrants().agent.$extend).toEqual(['role2', 'role3']);

        ac.removeRoles(['editor', 'agent']);
        expect(ac.getGrants().editor).toBeUndefined();
        expect(ac.getGrants().agent).toBeUndefined();
        expect(ac.getGrants().admin.$extend).not.toContain('editor');
        expect(ac.getGrants().admin.$extend).not.toContain('agent');

        expect(function () { ac.grant('roleX').extend('roleX'); }).toThrow();
        expect(function () { ac.grant(['admin2', 'roleX']).extend(['roleX', 'admin3']); }).toThrow();

        // console.log(JSON.stringify(ac.getGrants(), null, '  '));
    });

    it('should throw if grant or deny objects are invalid', function () {
        var o,
            ac = this.ac;

        o = {
            role: '', // invalid role, should be non-empty string or array
            resource: 'post',
            action: 'create:any',
            attributes: ['*'] // grant only
        };
        expect(function () { ac.grant(o); }).toThrow();
        expect(function () { ac.deny(o); }).toThrow();

        o = {
            role: 'moderator',
            resource: null, // invalid resource, should be non-empty string
            action: 'create:any',
            attributes: ['*'] // grant only
        };
        expect(function () { ac.grant(o); }).toThrow();
        expect(function () { ac.deny(o); }).toThrow();

        o = {
            role: 'admin',
            resource: 'post',
            action: 'put:any', // invalid action, should be create|read|update|delete
            attributes: ['*'] // grant only
        };
        expect(function () { ac.grant(o); }).toThrow();
        expect(function () { ac.deny(o); }).toThrow();

        o = {
            role: 'admin',
            resource: 'post',
            action: null, // invalid action, should be create|read|update|delete
            attributes: ['*'] // grant only
        };
        expect(function () { ac.grant(o); }).toThrow();
        expect(function () { ac.deny(o); }).toThrow();

        o = {
            role: 'admin',
            resource: 'post',
            action: 'create:all', // invalid possession, should be any|own or omitted
            attributes: ['*'] // grant only
        };
        expect(function () { ac.grant(o); }).toThrow();
        expect(function () { ac.deny(o); }).toThrow();

        o = {
            role: 'admin2',
            resource: 'post',
            action: 'create', // possession omitted, will be set to any
            attributes: ['*'] // grant only
        };
        expect(function () { ac.grant(o); }).not.toThrow();
        expect(ac.can('admin2').createAny('post').granted).toEqual(true);
        // possession "any" will also return granted=true for "own"
        expect(ac.can('admin2').createOwn('post').granted).toEqual(true);
        expect(function () { ac.deny(o); }).not.toThrow();

    });

    it('should filter granted attributes', function () {
        var ac = this.ac,
            attrs = ['*', '!account.balance.credit', '!account.id', '!secret'],
            data = {
                name: 'Company, LTD.',
                address: {
                    city: 'istanbul',
                    country: 'TR'
                },
                account: {
                    id: 33,
                    taxNo: 12345,
                    balance: {
                        credit: 100,
                        deposit: 0
                    }
                },
                secret: {
                    value: 'hidden'
                }
            };
        ac.grant('user').createOwn('company', attrs);
        var permission = ac.can('user').createOwn('company');
        expect(permission.granted).toEqual(true);
        var filtered = permission.filter(data);
        expect(filtered.name).toEqual(jasmine.any(String));
        expect(filtered.address).toEqual(jasmine.any(Object));
        expect(filtered.address.city).toEqual('istanbul');
        expect(filtered.account).toBeDefined();
        expect(filtered.account.id).toBeUndefined();
        expect(filtered.account.balance).toBeDefined();
        expect(filtered.account.credit).toBeUndefined();
        expect(filtered.secret).toBeUndefined();
    });

});
