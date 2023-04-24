import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MyMongodbDataSource} from '../datasources';
import {User, UserRelations} from '../models';

export class UsersRepository extends DefaultCrudRepository<
    User,
    typeof User.prototype.id,
    UserRelations
> {
    constructor(@inject('datasources.myMongodb') dataSource: MyMongodbDataSource) {
        super(User, dataSource);
    }
}
