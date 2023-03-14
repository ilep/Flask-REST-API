"""create role related tables

Revision ID: b9576629e182
Revises: 
Create Date: 2023-03-14 14:33:33.742775

"""
from alembic import op, context
import sqlalchemy as sa

import pandas

# revision identifiers, used by Alembic.
revision = 'b9576629e182'
down_revision = None
branch_labels = None
depends_on = None


def print_sql_constraints(kw=None, flag="before"):
    url = context.config.get_main_option("sqlalchemy.url")
    engine = sa.create_engine(url)

    sql_constraints = '''
    select COLUMN_NAME, CONSTRAINT_NAME, REFERENCED_COLUMN_NAME, REFERENCED_TABLE_NAME
    from information_schema.KEY_COLUMN_USAGE
    where TABLE_NAME = 'user_role' and constraint_schema='%s';
    ''' %  engine.url.database
    
    with engine.connect() as connection:
        df = pandas.read_sql(sa.text(sql_constraints), con=connection)
        
        if kw is not None:
            df = df.loc[(df['CONSTRAINT_NAME'].str.contains(kw))]
      
        print("="*25 + (" %s " % flag) + "="*25)
        print(df)
        print("="*60)
        print("\n"*3)




def upgrade() -> None:
    
    print_sql_constraints(kw='fk', flag="before")
    
    op.create_table(
        'role',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(50), unique=True)
    )

    op.create_table(
        'user_role',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id', ondelete='CASCADE')),
        sa.Column('role_id', sa.Integer, sa.ForeignKey('role.id', ondelete='CASCADE'))
    )
    
    print_sql_constraints(kw='fk', flag="after")
    

def downgrade() -> None:
    
    print_sql_constraints(kw='fk', flag="before")
    
    op.drop_table('user_role')
    op.drop_table('role')
    
    
    print_sql_constraints(kw='fk', flag="after")
    