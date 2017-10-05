/**
 *  Test Suite: AccessControl (Core)
 *  @author   Onur Yıldırım <onur@cutepilot.com>
 */

const AccessControl = require('../lib').AccessControl;
const Utils = require('../lib/utils');
const utils = Utils.utils;
const RESERVED_KEYWORDS = Utils.RESERVED_KEYWORDS;

function expectACError(fn, errMsg) {
    expect(fn).toThrow();
    try {
        fn();
    } catch (err) {
        expect(err instanceof AccessControl.Error).toEqual(true);
        expect(AccessControl.isACError(err)).toEqual(true);
        if (errMsg) expect(err.message).toContain(errMsg);
    }
}

describe('Test Suite: Access Control', function () {
    'use strict';

    // grant list fetched from DB (to be converted to a valid grants object)
    let grantList = [
        { role: 'admin', resource: 'video', action: 'create:any', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'read:any', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'update:any', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'delete:any', attributes: ['*'] },

        { role: 'user', resource: 'video', action: 'create:own', attributes: '*, !id' }, // comma-separated attrs
        { role: 'user', resource: 'video', action: 'read:any', attributes: '*; !id' }, // semi-colon separated attrs
        { role: 'user', resource: 'video', action: 'update:own', attributes: ['*', '!id'] }, // Array attrs
        { role: 'user', resource: 'video', action: 'delete:own', attributes: ['*'] }
    ];

    // valid grants object
    let grantsObject = {
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

    it('should throw on invalid grants object', function () {
        const ac = this.ac;

        // `undefined` does/should not throw due to default value
        let invalid = [null, undefined, true, false, '', NaN, new Date(), function () {}];
        invalid.forEach(o => {
            expectACError(() => new AccessControl(o));
            expectACError(() => ac.setGrants(o));
        });

        // omitting is allowed (results in empty grants object: {})
        expect(() => new AccessControl()).not.toThrow();
        // empty object is allowed
        expect(() => new AccessControl({})).not.toThrow();
        expect(new AccessControl({}).getGrants()).toEqual({});
        // explicit undefined is not allowed
        expectACError(() => new AccessControl(undefined));

        // Initial Grants as an Object
        // ----------------------------

        expectACError(() => ac.setGrants({ '$': {} }));
        expectACError(() => ac.setGrants({ '$extend': {} }));
        // if $extend is set to an array of strings or empty array, it's valid
        // (contains inherited roles)
        expect(() => ac.setGrants({ '$extend': [] })).not.toThrow();
        // empty string in the $extend array is not allowed
        expectACError(() => ac.setGrants({ '$extend': [''] }));

        // role definition must be an object
        invalid = [[], undefined, null, true, new Date];
        invalid.forEach(o => {
            expectACError(() => ac.setGrants({ role: invalid }));
        });
        // resource definition must be an object
        invalid.forEach(o => {
            expectACError(() => ac.setGrants({ role: { resource: invalid } }));
        });
        // actions should be one of Action enumeration (with or without possession)
        expectACError(() => ac.setGrants({ role: { resource: { 'invalid': [] } } }));
        expectACError(() => ac.setGrants({ role: { resource: { 'remove:any': [] } } }));
        // missing colon
        expectACError(() => ac.setGrants({ role: { resource: { 'createany': [] } } }));
        // action/possession is ok but value is invalid
        invalid = [undefined, null, true, new Date, {}];
        invalid.forEach(o => {
            expectACError(() => ac.setGrants({ role: { resource: { 'create:any': invalid } } }));;
        });

        // Initial Grants as an Array
        // ----------------------------

        // empty array is allowed. a flat list will be converted to inner grants
        // object. empty array results in {}.
        expect(() => new AccessControl([])).not.toThrow();
        expect(new AccessControl([]).getGrants()).toEqual({});
        // array should be an array of objects
        expectACError(() => ac.setGrants([ [] ]));
        // no empty grant items
        expectACError(() => ac.setGrants([ {} ]));
        // e.g. $extend is not allowed for role or resource names. it's a reserved keyword.
        RESERVED_KEYWORDS.forEach(name => {
            expectACError(() => ac.setGrants([ { role: name, resource: 'video', action: 'create:any' } ]));
            expectACError(() => ac.setGrants([ { role: 'admin', resource: name, action: 'create:any' } ]));
            expectACError(() => ac.setGrants([ { role: 'admin', resource: 'video', action: name } ]));
        });

        // attributes property can be omitted
        expect(() => ac.setGrants([ { role: 'admin', resource: 'video', action: 'create:any' } ])).not.toThrow();
        // role, resource or action properties cannot be omitted
        expectACError(() => ac.setGrants([ { resource: 'video', action: 'create:any' } ]));
        expectACError(() => ac.setGrants([ { role: 'admin', resource: 'video' } ]));
        expectACError(() => ac.setGrants([ { role: 'admin', action: 'create:any' } ]));
    });

    it('should construct with grants array or object, output a grants object', function () {
        let ac = new AccessControl(grantList);
        let grants = ac.getGrants();
        expect(utils.type(grants)).toEqual('object');
        expect(utils.type(grants.admin)).toEqual('object');
        expect(grants.admin.video['create:any']).toEqual(jasmine.any(Array));
        // console.log(grants);

        ac = new AccessControl(grantsObject);
        grants = ac.getGrants();
        expect(utils.type(grants)).toEqual('object');
        expect(utils.type(grants.admin)).toEqual('object');
        expect(grants.admin.video['create:any']).toEqual(jasmine.any(Array));
    });

    it('should reset grants with #reset() only', function () {
        let ac = new AccessControl(grantsObject);
        expect(ac.getRoles().length).toBeGreaterThan(0); // make sure not empty
        expectACError(() => ac.setGrants());
        expectACError(() => ac.setGrants(null));
        expectACError(() => ac.setGrants(undefined));
        expect(ac.reset().getGrants()).toEqual({});
        expect(ac.setGrants({}).getGrants()).toEqual({});
    });


    it('should add grants from flat list (db), check/remove roles and resources', function () {
        const ac = this.ac;
        ac.setGrants(grantList);
        // console.log('grants', ac.getGrants());
        // console.log('resources', ac.getResources());
        // console.log('roles', ac.getRoles());

        // comma/semi-colon separated should be turned into string arrays
        let attrs1 = ac.can('user').createOwn('video').attributes;
        let attrs2 = ac.can('user').readAny('video').attributes;
        let attrs3 = ac.can('user').updateOwn('video').attributes;
        // console.log(attrs1);
        expect(attrs1.length).toEqual(2);
        expect(attrs2.length).toEqual(2);
        expect(attrs3.length).toEqual(2);

        // check roles & resources
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
        const ac = this.ac,
            attrs = ['*', '!size'];

        ac.grant('user').createAny('photo', attrs);
        expect(ac.getGrants().user.photo['create:any']).toEqual(attrs);
        expect(ac.can('user').createAny('photo').attributes).toEqual(attrs);

        ac.deny('user').createAny('photo', attrs); // <- denied even with attrs
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
        // deny multiple roles (comma-separated) the same permission for the same resource
        ac.deny('user, admin').readAny('photo');
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
        const ac = this.ac,
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
        const ac = this.ac,
            attrs = ['*'];

        let o1 = {
            role: 'moderator',
            resource: 'post',
            action: 'create:any', // action:possession
            attributes: ['*'] // grant only
        };
        let o2 = {
            role: 'moderator',
            resource: 'news',
            action: 'read', // separate action
            possession: 'own', // separate possession
            attributes: ['*'] // grant only
        };
        let o3 = {
            role: 'moderator',
            resource: 'book',
            // no action/possession set
            attributes: ['*'] // grant only
        };

        ac.grant(o1).grant(o2);
        ac.grant(o3).updateAny();

        expect(ac.can('moderator').createAny('post').granted).toEqual(true);
        expect(ac.can('moderator').readOwn('news').granted).toEqual(true);
        expect(ac.can('moderator').updateAny('book').granted).toEqual(true);

        ac.deny(o1).deny(o2);
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
        const ac = this.ac;
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
        const ac = this.ac;
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

    it('deny should auto-set attributes to []', function () {
        const ac = this.ac;
        ac.deny('user').createAny('book', ['*']);
        expect(ac.getGrants().user.book['create:any']).toEqual([]);
    });

    it('should grant comma/semi-colon separated roles', function () {
        const ac = this.ac;
        // also supporting comma/semi-colon separated roles
        ac.grant('role2; role3, editor; viewer, agent').createOwn('book');
        expect(ac.hasRole('role3')).toEqual(true);
        expect(ac.hasRole('editor')).toEqual(true);
        expect(ac.hasRole('agent')).toEqual(true);
    });

    it('permission should also return queried role(s) and resource', function () {
        const ac = this.ac;
        // also supporting comma/semi-colon separated roles
        ac.grant('foo, bar').createOwn('baz');
        expect(ac.can('bar').createAny('baz').granted).toEqual(false);
        expect(ac.can('bar').createOwn('baz').granted).toEqual(true);
        // returned permission should provide queried role(s) as array
        expect(ac.can('foo').create('baz').roles).toContain('foo');
        // returned permission should provide queried resource
        expect(ac.can('foo').create('baz').resource).toEqual('baz');
        // create is createAny. but above only returns the queried value, not the result.
    });

    it('should extend / remove roles', function () {
        const ac = this.ac;

        ac.grant('admin').createOwn('book');
        ac.extendRole('onur', 'admin');
        expect(ac.getGrants().onur.$extend.length).toEqual(1);
        expect(ac.getGrants().onur.$extend[0]).toEqual('admin');

        ac.grant('role2, role3, editor, viewer, agent').createOwn('book');

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

        expect(() => ac.grant('roleX').extend('roleX')).toThrow();
        expect(() => ac.grant(['admin2', 'roleX']).extend(['roleX', 'admin3'])).toThrow();

        // console.log(JSON.stringify(ac.getGrants(), null, '  '));
    });

    it('should extend before or after resource permissions are granted', function () {
        let ac;

        function init() {
            ac = new AccessControl();
            // create the roles
            ac.grant(['user', 'admin']);
            expect(ac.getRoles().length).toEqual(2);
        }

        // case #1
        init();
        ac.grant('admin').extend('user') // assuming user role already exists
            .grant('user').createOwn('video');
        expect(ac.can('admin').createOwn('video').granted).toEqual(true);

        // case #2
        init();
        ac.grant('user').createOwn('video')
            .grant('admin').extend('user');
        expect(ac.can('admin').createOwn('video').granted).toEqual(true);
    });

    it('should extend multi-level (deep) roles', function () {
        let ac = new AccessControl();
        ac.grant('viewer').readAny('devices');
        ac.grant('ops').extend('viewer').updateAny('devices', ['*', '!id']);
        ac.grant('admin').extend('ops').deleteAny('devices');
        ac.grant('superadmin').extend(['admin', 'ops']).createAny('devices');
        // ac.extendRole(['ops', 'admin'], 'viewer');

        expect(ac.can('ops').readAny('devices').granted).toEqual(true);
        expect(ac.can('admin').readAny('devices').granted).toEqual(true);
        expect(ac.can('admin').updateAny('devices').granted).toEqual(true);
        expect(ac.can('superadmin').readAny('devices').granted).toEqual(true);

        expect(ac.can('superadmin').updateAny('devices').attributes).toEqual(['*', '!id']);
        ac.grant('superadmin').updateAny('devices', ['*']);
        expect(ac.can('superadmin').updateAny('devices').attributes).toEqual(['*']);

        expect(ac.getInheritedRolesOf('viewer')).toEqual([])
        expect(ac.getInheritedRolesOf('ops')).toEqual(['viewer'])
        expect(ac.getInheritedRolesOf('admin')).toEqual(['ops', 'viewer'])
        expect(ac.getInheritedRolesOf('superadmin')).toEqual(['admin', 'ops', 'viewer'])

        // console.log(JSON.stringify(ac.getGrants(), null, '  '));
    });

    it('should throw if target role or inherited role does not exit', function () {
        const ac = this.ac;
        expectACError(() => ac.grant().createOwn());
        ac.setGrants(grantsObject);
        expectACError(() => ac.can('invalid-role').createOwn('video'), 'Role not found');
        expectACError(() => ac.grant('user').extend('invalid-role'));
        expectACError(() => ac.grant('user').extend(['invalid1', 'invalid2']));
    });

    it('should throw on reserved names', function () {
        const ac = new AccessControl();
        RESERVED_KEYWORDS.forEach(name => {
            expectACError(() => ac.grant(name));
            expectACError(() => ac.deny(name));
            expectACError(() => ac.grant().role(name));
            expectACError(() => ac.grant('role').resource(name));
        });
        expectACError(() => new AccessControl({ $: [] }));
        expectACError(() => new AccessControl({ $extend: {} }));
    });

    it('should throw if a role attempts to extend itself', function () {
        const ac = this.ac;
        expectACError(() => ac.grant('user').extend('user'));
    });

    it('should throw on cross-role inheritance', function () {
        let ac = new AccessControl();
        ac.grant(['user', 'admin']).createOwn('video');
        // make sure roles are created
        expect(ac.getRoles().length).toEqual(2);

        expectACError(() => {
            ac.grant('admin').extend('user');
            ac.grant('user').extend('admin');
        });
        // console.log(ac.getGrants());
    });

    it('should throw if grant or deny objects are invalid', function () {
        let o,
            ac = this.ac;

        o = {
            role: '', // invalid role, should be non-empty string or array
            resource: 'post',
            action: 'create:any',
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();
        expect(() => ac.deny(o)).toThrow();

        o = {
            role: 'moderator',
            resource: null, // invalid resource, should be non-empty string
            action: 'create:any',
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();
        expect(() => ac.deny(o)).toThrow();

        o = {
            role: 'admin',
            resource: 'post',
            action: 'put:any', // invalid action, should be create|read|update|delete
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();
        expect(() => ac.deny(o)).toThrow();

        o = {
            role: 'admin',
            resource: 'post',
            action: null, // invalid action, should be create|read|update|delete
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();
        expect(() => ac.deny(o)).toThrow();

        o = {
            role: 'admin',
            resource: 'post',
            action: 'create:all', // invalid possession, should be any|own or omitted
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();
        expect(() => ac.deny(o)).toThrow();

        o = {
            role: 'admin2',
            resource: 'post',
            action: 'create', // possession omitted, will be set to any
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).not.toThrow();
        expect(ac.can('admin2').createAny('post').granted).toEqual(true);
        // possession "any" will also return granted=true for "own"
        expect(ac.can('admin2').createOwn('post').granted).toEqual(true);
        expect(() => ac.deny(o)).not.toThrow();

    });

    it('Check with multiple roles changes grant list (issue #2)', function () {
        const ac = this.ac;
        ac.grant('admin').updateAny('video')
            .grant(['user', 'admin']).updateOwn('video');

        // Admin can update any video
        expect(ac.can(['admin']).updateAny('video').granted).toEqual(true);

        // console.log('grants before', JSON.stringify(ac.getGrants(), null, '  '));

        // This check actually changes the underlying grants
        ac.can(['user', 'admin']).updateOwn('video');

        // console.log('grants after', JSON.stringify(ac.getGrants(), null, '  '));

        // Admin can update any or own video
        expect(ac.can(['admin']).updateAny('video').granted).toEqual(true);
        expect(ac.can(['admin']).updateOwn('video').granted).toEqual(true);
    });

    it('should grant/deny multiple roles and multiple resources', function () {
        const ac = this.ac;

        ac.grant('admin, user').createAny('profile, video');
        expect(ac.can('admin').createAny('profile').granted).toEqual(true);
        expect(ac.can('admin').createAny('video').granted).toEqual(true);
        expect(ac.can('user').createAny('profile').granted).toEqual(true);
        expect(ac.can('user').createAny('video').granted).toEqual(true);

        ac.grant('admin, user').createAny('profile, video', '*,!id');
        expect(ac.can('admin').createAny('profile').attributes).toEqual(['*', '!id']);
        expect(ac.can('admin').createAny('video').attributes).toEqual(['*', '!id']);
        expect(ac.can('user').createAny('profile').attributes).toEqual(['*', '!id']);
        expect(ac.can('user').createAny('video').attributes).toEqual(['*', '!id']);

        ac.deny('admin, user').readAny('photo, book', '*,!id');
        expect(ac.can('admin').readAny('photo').attributes).toEqual([]);
        expect(ac.can('admin').readAny('book').attributes).toEqual([]);
        expect(ac.can('user').readAny('photo').attributes).toEqual([]);
        expect(ac.can('user').readAny('book').attributes).toEqual([]);

        expect(ac.can('user').createAny('non-existent').granted).toEqual(false);

        // console.log(JSON.stringify(ac.getGrants(), null, '  '));
    });

    it('should filter granted attributes', function () {
        const ac = this.ac;
        const attrs = ['*', '!account.balance.credit', '!account.id', '!secret'];
        const data = {
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
        let permission = ac.can('user').createOwn('company');
        expect(permission.granted).toEqual(true);
        let filtered = permission.filter(data);
        expect(filtered.name).toEqual(jasmine.any(String));
        expect(filtered.address).toEqual(jasmine.any(Object));
        expect(filtered.address.city).toEqual('istanbul');
        expect(filtered.account).toBeDefined();
        expect(filtered.account.id).toBeUndefined();
        expect(filtered.account.balance).toBeDefined();
        expect(filtered.account.credit).toBeUndefined();
        expect(filtered.secret).toBeUndefined();
    });

    it('should union granted attributes for extended roles, on query', function () {
        const ac = this.ac;
        const restrictedAttrs = ['*', '!id', '!pwd'];
        // grant user restricted attrs
        ac.grant('user').updateAny('video', restrictedAttrs)
            // extend admin with user as is (same attributes)
            .grant('admin').extend('user');
        // admin should have the same restricted attributes
        expect(ac.can('admin').updateAny('video').attributes).toEqual(restrictedAttrs);
        // grant admin unrestricted attrs (['*'])
        ac.grant('admin').updateAny('video');
        // union'ed attributes should be ['*']
        expect(ac.can('admin').updateAny('video').attributes).toEqual(['*']);

        ac.grant('editor').updateAny('video', ['*', '!pwd', 'title']).extend('user');
        // 'title' is redundant since we have '*'.
        // '!pwd' exists in both attribute lists, so it should exist in union.
        expect(ac.can('editor').updateAny('video').attributes).toEqual(['*', '!pwd']);

        ac.grant('role1').createOwn('photo', ['image', 'name'])
            .grant('role2').createOwn('photo', ['name', '!location']) // '!location' is redundant here
            .grant('role3').createOwn('photo', ['*', '!location'])
            .grant('role4').extend(['role1', 'role2'])
            .grant('role5').extend(['role1', 'role2', 'role3']);
            // console.log(ac.can('role4').createOwn('photo').attributes);
        // expect(ac.can('role4').createOwn('photo').attributes).toEqual(['image', 'name']);
        expect(ac.can('role5').createOwn('photo').attributes).toEqual(['*', '!location']);
    });

    it('should filter given data (static filter method)', function () {
        let o = {
            name: 'John',
            age: 30,
            account: {
                id: 1,
                country: 'US'
            }
        };
        let x = AccessControl.filter(o, ['*', '!account.id', '!age']);
        expect(x.name).toEqual('John');
        expect(x.account.id).toBeUndefined();
        expect(x.account.country).toEqual('US');

        expect(o.account.id).toEqual(1);
        expect(o).not.toEqual(x);
    });

    it('should lock AccessControl instance', function () {
        let ac;

        function test() {
            expectACError(() => ac.setGrants({}));
            expectACError(() => ac.reset());
            expectACError(() => ac.grant('editor'));
            expectACError(() => ac.deny('admin'));
            expectACError(() => ac.extendRole('admin', 'user'));
            expectACError(() => ac.removeRoles(['admin']));
            expectACError(() => ac.removeResources(['video']));

            expect(ac.getRoles()).toContain('user');
            expect(ac.getRoles()).toContain('admin');
            expect(ac.getResources()).toContain('video');
            expect(ac.getExtendedRolesOf('admin')).not.toContain('user');
        }

        // locking with Access#lock
        ac = new AccessControl();
        ac.grant('user').createAny('video')
            .grant('admin').createAny('photo')
            .lock();
        test();


        // locking with AccessControl#lock
        ac = new AccessControl();
        ac.grant('user').createAny('video')
            .grant('admin').createAny('photo');
        ac.lock();
        test();
    });

});
