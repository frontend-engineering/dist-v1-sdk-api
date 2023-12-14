import { z } from "zod";
import { ZodTypeDef } from "zod/lib/types";
import { FloSchemaObject } from './types';
declare module 'zod' {
    interface ZodSchema<Output = any, Def extends ZodTypeDef = ZodTypeDef, Input = Output> {
        openapi<T extends ZodSchema<Output, Def, Input>>(this: T, metadata: Partial<FloSchemaObject>): T;
    }
}
export declare function extendZodWithOpenApi(zod: typeof z, forceOverride?: boolean): void;
