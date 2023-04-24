import {Entity, model, property} from '@loopback/repository';

@model()
export class Product extends Entity {
    @property({
        type: 'string',
        required: true,
    })
    name: string;

    @property({
        type: 'string',
        required: true,
    })
    category: string;

    @property({
        type: 'string',
        required: true,
    })
    brand: string;

    @property({
        type: 'number',
        required: true,
    })
    price: number;

    @property({
        type: 'string',
        id: true,
        generated: true,
    })
    id?: string;

    constructor(data?: Partial<Product>) {
        super(data);
    }
}

export interface ProductRelations {
    // describe navigational properties here
}

export type ProductWithRelations = Product & ProductRelations;
