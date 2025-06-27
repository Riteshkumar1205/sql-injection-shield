# create_dummy_model.py
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

model = Sequential([
    Dense(32, activation='relu', input_shape=(100,)),
    Dense(1, activation='sigmoid')
])

model.save('cnn_model.h5')
