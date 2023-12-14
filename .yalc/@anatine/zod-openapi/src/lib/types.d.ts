import { SchemaObject } from "openapi3-ts";
export type FloSchemaObject = SchemaObject & {
    [x: string | number | symbol]: any;
};
