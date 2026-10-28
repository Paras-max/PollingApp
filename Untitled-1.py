class Car:
    def __init__(self, brand, model):
        self.brand = brand
        self.model = model
        self.speed = 0
    
    def accelerate(self):
        self.speed += 10
        return f"{self.brand} {self.model} is now moving at {self.speed} km/h"
    
    def brake(self):
        if self.speed >= 10:
            self.speed -= 10
        else:
            self.speed = 0
        return f"{self.brand} {self.model} slowed down to {self.speed} km/h"
my_car = Car("Mercedes", "Benz C-Class")
print(my_car.accelerate())  
print(my_car.accelerate())  
print(my_car.brake())       