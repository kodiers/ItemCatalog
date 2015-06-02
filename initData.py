from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base

engine = create_engine('sqlite:///itemcatalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

Soccer = Category(name="Soccer")
session.add(Soccer)
session.commit()

Basketball = Category(name="Basketball")
session.add(Basketball)
session.commit()

Baseball = Category(name="Baseball")
session.add(Baseball)
session.commit()

Frisbee = Category(name="Frisbee")
session.add(Frisbee)
session.commit()

Snowboarding = Category(name="Snowboarding")
session.add(Snowboarding)
session.commit()

RockClimbing = Category(name="Rock Climbing")
session.add(RockClimbing)
session.commit()

Football = Category(name="Football")
session.add(Football)
session.commit()

Skating = Category(name="Skating")
session.add(Skating)
session.commit()

Hockey = Category(name="Hockey")
session.add(Hockey)
session.commit()

print("Categories created!")