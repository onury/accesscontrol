'use strict';

/**
 *  Test Helper
 *  @author   Onur Yıldırım <onur@cutepilot.com>
 */

import { AccessControl } from '../src';

const helper = {
    expectACError(fn: any, errMsg?: string) {
        expect(fn).toThrow();
        try {
            fn();
        } catch (err) {
            expect(err instanceof AccessControl.Error).toEqual(true);
            expect(AccessControl.isAccessControlError(err)).toEqual(true);
            expect(AccessControl.isACError(err)).toEqual(true); // alias test
            if (errMsg) expect(err.message).toContain(errMsg);
        }
    }

};

export { helper };
