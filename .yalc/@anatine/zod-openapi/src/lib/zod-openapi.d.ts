import type { FloSchemaObject } from './types';
import { ZodTypeAny } from 'zod';
export interface OpenApiZodAny extends ZodTypeAny {
    metaOpenApi?: FloSchemaObject | FloSchemaObject[];
}
export declare function extendApi<T extends OpenApiZodAny>(schema: T, SchemaObject?: FloSchemaObject): T;
export declare function generateSchema(zodRef: OpenApiZodAny, useOutput?: boolean): FloSchemaObject;
